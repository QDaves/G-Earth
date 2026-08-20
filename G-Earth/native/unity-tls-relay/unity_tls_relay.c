#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"

static const uint16_t unity_signature_algorithms[] = {
    MBEDTLS_TLS1_3_SIG_ECDSA_SECP521R1_SHA512,
    MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA512,
    MBEDTLS_TLS1_3_SIG_ECDSA_SECP384R1_SHA384,
    MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA384,
    MBEDTLS_TLS1_3_SIG_ECDSA_SECP256R1_SHA256,
    MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA256,
    MBEDTLS_TLS1_3_SIG_NONE
};

struct parent_watch {
    HANDLE parent;
    HANDLE stop;
};

static DWORD WINAPI watch_parent(void *value)
{
    struct parent_watch *watch = value;
    HANDLE handles[] = { watch->parent, watch->stop };
    if (WaitForMultipleObjects(2, handles, FALSE, INFINITE) == WAIT_OBJECT_0) {
        ExitProcess(0);
    }
    return 0;
}

static void print_mbedtls_error(const char *stage, int code)
{
    char message[256];
    mbedtls_strerror(code, message, sizeof(message));
    fprintf(stderr, "ERROR %s -0x%04x %s\n", stage, (unsigned int) -code, message);
}

static int utf8_to_wide(const char *value, wchar_t **wide)
{
    int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value, -1, NULL, 0);
    if (length == 0) {
        return 0;
    }
    *wide = calloc((size_t) length, sizeof(wchar_t));
    if (*wide == NULL) {
        return 0;
    }
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value, -1, *wide, length) == 0) {
        free(*wide);
        *wide = NULL;
        return 0;
    }
    return 1;
}

static int verify_server_certificate(mbedtls_ssl_context *ssl, const char *host)
{
    const mbedtls_x509_crt *certificate = mbedtls_ssl_get_peer_cert(ssl);
    HCERTSTORE store = NULL;
    PCCERT_CONTEXT leaf = NULL;
    PCCERT_CHAIN_CONTEXT chain = NULL;
    CERT_CHAIN_PARA chain_parameters;
    SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl_parameters;
    CERT_CHAIN_POLICY_PARA policy_parameters;
    CERT_CHAIN_POLICY_STATUS policy_status;
    wchar_t *wide_host = NULL;
    int valid = 0;

    if (certificate == NULL || !utf8_to_wide(host, &wide_host)) {
        goto done;
    }

    store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (store == NULL) {
        goto done;
    }

    for (const mbedtls_x509_crt *current = certificate; current != NULL; current = current->next) {
        PCCERT_CONTEXT added = NULL;
        if (!CertAddEncodedCertificateToStore(
                store,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                current->raw.p,
                (DWORD) current->raw.len,
                CERT_STORE_ADD_ALWAYS,
                &added)) {
            goto done;
        }
        if (leaf == NULL) {
            leaf = CertDuplicateCertificateContext(added);
        }
        CertFreeCertificateContext(added);
    }

    if (leaf == NULL) {
        goto done;
    }

    memset(&chain_parameters, 0, sizeof(chain_parameters));
    chain_parameters.cbSize = sizeof(chain_parameters);
    if (!CertGetCertificateChain(
            NULL,
            leaf,
            NULL,
            store,
            &chain_parameters,
            CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY,
            NULL,
            &chain)) {
        goto done;
    }

    memset(&ssl_parameters, 0, sizeof(ssl_parameters));
    ssl_parameters.cbSize = sizeof(ssl_parameters);
    ssl_parameters.dwAuthType = AUTHTYPE_SERVER;
    ssl_parameters.pwszServerName = wide_host;

    memset(&policy_parameters, 0, sizeof(policy_parameters));
    policy_parameters.cbSize = sizeof(policy_parameters);
    policy_parameters.pvExtraPolicyPara = &ssl_parameters;

    memset(&policy_status, 0, sizeof(policy_status));
    policy_status.cbSize = sizeof(policy_status);
    if (!CertVerifyCertificateChainPolicy(
            CERT_CHAIN_POLICY_SSL,
            chain,
            &policy_parameters,
            &policy_status)) {
        goto done;
    }

    valid = policy_status.dwError == 0;

done:
    if (chain != NULL) {
        CertFreeCertificateChain(chain);
    }
    if (leaf != NULL) {
        CertFreeCertificateContext(leaf);
    }
    if (store != NULL) {
        CertCloseStore(store, 0);
    }
    free(wide_host);
    return valid;
}

static int parent_is_alive(HANDLE parent)
{
    return parent == NULL || WaitForSingleObject(parent, 0) == WAIT_TIMEOUT;
}

static int local_port(const mbedtls_net_context *listener)
{
    struct sockaddr_in address;
    int length = sizeof(address);
    memset(&address, 0, sizeof(address));
    if (getsockname((SOCKET) listener->fd, (struct sockaddr *) &address, &length) != 0) {
        return 0;
    }
    return ntohs(address.sin_port);
}

static int relay(
        mbedtls_ssl_context *ssl,
        mbedtls_net_context *remote,
        mbedtls_net_context *local,
        HANDLE parent)
{
    unsigned char upstream_data[65536];
    unsigned char local_data[65536];
    size_t upstream_offset = 0;
    size_t upstream_length = 0;
    size_t local_offset = 0;
    size_t local_length = 0;
    int upstream_write_wait = 2;
    int upstream_read_wait = 1;
    int remote_closed = 0;

    if (mbedtls_net_set_nonblock(remote) != 0 || mbedtls_net_set_nonblock(local) != 0) {
        return -1;
    }

    while (parent_is_alive(parent)) {
        fd_set readers;
        fd_set writers;
        struct timeval timeout;
        SOCKET remote_socket = (SOCKET) remote->fd;
        SOCKET local_socket = (SOCKET) local->fd;

        FD_ZERO(&readers);
        FD_ZERO(&writers);

        if (upstream_length == 0) {
            FD_SET(local_socket, &readers);
        } else if (upstream_write_wait == 1) {
            FD_SET(remote_socket, &readers);
        } else {
            FD_SET(remote_socket, &writers);
        }

        if (local_length > local_offset) {
            FD_SET(local_socket, &writers);
        } else if (!remote_closed && mbedtls_ssl_get_bytes_avail(ssl) == 0) {
            if (upstream_read_wait == 2) {
                FD_SET(remote_socket, &writers);
            } else {
                FD_SET(remote_socket, &readers);
            }
        }

        timeout.tv_sec = 0;
        timeout.tv_usec = 100000;
        int selected = select(0, &readers, &writers, NULL, &timeout);
        if (selected == SOCKET_ERROR) {
            return -1;
        }

        if (local_length > local_offset && FD_ISSET(local_socket, &writers)) {
            int written = send(
                local_socket,
                (const char *) local_data + local_offset,
                (int) (local_length - local_offset),
                0);
            if (written == SOCKET_ERROR) {
                int error = WSAGetLastError();
                if (error != WSAEWOULDBLOCK) {
                    return -1;
                }
            } else {
                local_offset += (size_t) written;
                if (local_offset == local_length) {
                    local_offset = 0;
                    local_length = 0;
                    if (remote_closed) {
                        return 0;
                    }
                }
            }
        }

        if (upstream_length > 0
                && ((upstream_write_wait == 1 && FD_ISSET(remote_socket, &readers))
                    || (upstream_write_wait == 2 && FD_ISSET(remote_socket, &writers)))) {
            int written = mbedtls_ssl_write(
                ssl,
                upstream_data + upstream_offset,
                upstream_length - upstream_offset);
            if (written > 0) {
                upstream_offset += (size_t) written;
                upstream_write_wait = 2;
                if (upstream_offset == upstream_length) {
                    upstream_offset = 0;
                    upstream_length = 0;
                }
            } else if (written == MBEDTLS_ERR_SSL_WANT_READ) {
                upstream_write_wait = 1;
            } else if (written == MBEDTLS_ERR_SSL_WANT_WRITE) {
                upstream_write_wait = 2;
            } else {
                return written;
            }
        }

        if (upstream_length == 0 && FD_ISSET(local_socket, &readers)) {
            int received = recv(local_socket, (char *) upstream_data, sizeof(upstream_data), 0);
            if (received == 0) {
                mbedtls_ssl_close_notify(ssl);
                return 0;
            }
            if (received == SOCKET_ERROR) {
                int error = WSAGetLastError();
                if (error != WSAEWOULDBLOCK) {
                    return -1;
                }
            } else {
                upstream_offset = 0;
                upstream_length = (size_t) received;
                upstream_write_wait = 2;
            }
        }

        if (local_length == 0 && !remote_closed
                && (mbedtls_ssl_get_bytes_avail(ssl) > 0
                    || (upstream_read_wait == 1 && FD_ISSET(remote_socket, &readers))
                    || (upstream_read_wait == 2 && FD_ISSET(remote_socket, &writers)))) {
            int received = mbedtls_ssl_read(ssl, local_data, sizeof(local_data));
            if (received > 0) {
                local_offset = 0;
                local_length = (size_t) received;
                upstream_read_wait = 1;
            } else if (received == 0 || received == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                remote_closed = 1;
                if (local_length == 0) {
                    return 0;
                }
            } else if (received == MBEDTLS_ERR_SSL_WANT_READ) {
                upstream_read_wait = 1;
            } else if (received == MBEDTLS_ERR_SSL_WANT_WRITE) {
                upstream_read_wait = 2;
            } else {
                return received;
            }
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context random;
    mbedtls_ssl_config configuration;
    mbedtls_ssl_context ssl;
    mbedtls_net_context remote;
    mbedtls_net_context listener;
    mbedtls_net_context local;
    HANDLE parent = NULL;
    HANDLE watcher = NULL;
    struct parent_watch watch = { 0 };
    int result = 1;
    int status;

    if (argc != 4) {
        fprintf(stderr, "ERROR usage unity-tls-relay host port parent-pid\n");
        return 2;
    }

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    parent = OpenProcess(SYNCHRONIZE, FALSE, (DWORD) strtoul(argv[3], NULL, 10));
    if (parent == NULL) {
        fprintf(stderr, "ERROR parent unavailable\n");
        return 3;
    }
    watch.parent = parent;
    watch.stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (watch.stop == NULL) {
        fprintf(stderr, "ERROR parent monitor unavailable\n");
        CloseHandle(parent);
        return 3;
    }
    watcher = CreateThread(NULL, 0, watch_parent, &watch, 0, NULL);
    if (watcher == NULL) {
        fprintf(stderr, "ERROR parent monitor unavailable\n");
        CloseHandle(watch.stop);
        CloseHandle(parent);
        return 3;
    }

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&random);
    mbedtls_ssl_config_init(&configuration);
    mbedtls_ssl_init(&ssl);
    mbedtls_net_init(&remote);
    mbedtls_net_init(&listener);
    mbedtls_net_init(&local);

    status = mbedtls_ctr_drbg_seed(
        &random,
        mbedtls_entropy_func,
        &entropy,
        (const unsigned char *) "unity-tls-relay",
        sizeof("unity-tls-relay") - 1);
    if (status != 0) {
        print_mbedtls_error("random", status);
        goto done;
    }

    status = mbedtls_ssl_config_defaults(
        &configuration,
        MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT);
    if (status != 0) {
        print_mbedtls_error("configuration", status);
        goto done;
    }

    mbedtls_ssl_conf_rng(&configuration, mbedtls_ctr_drbg_random, &random);
    mbedtls_ssl_conf_authmode(&configuration, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_min_tls_version(&configuration, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&configuration, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_sig_algs(&configuration, unity_signature_algorithms);

    status = mbedtls_ssl_setup(&ssl, &configuration);
    if (status != 0) {
        print_mbedtls_error("context", status);
        goto done;
    }

    status = mbedtls_ssl_set_hostname(&ssl, argv[1]);
    if (status != 0) {
        print_mbedtls_error("hostname", status);
        goto done;
    }

    status = mbedtls_net_connect(&remote, argv[1], argv[2], MBEDTLS_NET_PROTO_TCP);
    if (status != 0) {
        print_mbedtls_error("connect", status);
        goto done;
    }

    mbedtls_ssl_set_bio(&ssl, &remote, mbedtls_net_send, mbedtls_net_recv, NULL);
    status = mbedtls_ssl_handshake(&ssl);
    if (status != 0) {
        print_mbedtls_error("handshake", status);
        goto done;
    }

    if (!verify_server_certificate(&ssl, argv[1])) {
        fprintf(stderr, "ERROR certificate validation failed\n");
        goto done;
    }

    status = mbedtls_net_bind(&listener, "127.0.0.1", "0", MBEDTLS_NET_PROTO_TCP);
    if (status != 0) {
        print_mbedtls_error("listen", status);
        goto done;
    }

    int port = local_port(&listener);
    if (port == 0) {
        fprintf(stderr, "ERROR local port unavailable\n");
        goto done;
    }

    printf("READY %d\n", port);
    status = mbedtls_net_accept(&listener, &local, NULL, 0, NULL);
    if (status != 0) {
        print_mbedtls_error("accept", status);
        goto done;
    }

    status = relay(&ssl, &remote, &local, parent);
    if (status != 0) {
        print_mbedtls_error("relay", status);
        goto done;
    }

    result = 0;

done:
    mbedtls_net_free(&local);
    mbedtls_net_free(&listener);
    mbedtls_net_free(&remote);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&configuration);
    mbedtls_ctr_drbg_free(&random);
    mbedtls_entropy_free(&entropy);
    SetEvent(watch.stop);
    WaitForSingleObject(watcher, INFINITE);
    CloseHandle(watcher);
    CloseHandle(watch.stop);
    if (parent != NULL) {
        CloseHandle(parent);
    }
    return result;
}
