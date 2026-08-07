package gearth.app.protocol.connection.proxy.unity.standalone;

import gearth.protocol.HMessage;
import gearth.services.packet_info.PacketInfo;
import gearth.services.packet_info.PacketInfoManager;

import java.util.List;

record UnityHandshakeHeaders(
        int clientHello,
        int clientDhInit,
        int clientDhComplete,
        int serverDhInit,
        int serverDhComplete) {

    static UnityHandshakeHeaders from(PacketInfoManager packetInfoManager) {
        return new UnityHandshakeHeaders(
                require(packetInfoManager, HMessage.Direction.TOSERVER, "ClientHello"),
                require(packetInfoManager, HMessage.Direction.TOSERVER, "InitDiffieHandshake"),
                require(packetInfoManager, HMessage.Direction.TOSERVER, "CompleteDiffieHandshake"),
                require(packetInfoManager, HMessage.Direction.TOCLIENT, "DhInitHandshake"),
                require(packetInfoManager, HMessage.Direction.TOCLIENT, "DhCompleteHandshake"));
    }

    private static int require(
            PacketInfoManager packetInfoManager,
            HMessage.Direction direction,
            String name) {
        List<PacketInfo> matches = packetInfoManager.getAllPacketInfoFromName(direction, name);
        if (matches.size() != 1) {
            throw new IllegalStateException("Unity header must resolve exactly once: " + direction + ":" + name);
        }
        int header = matches.getFirst().getHeaderId();
        if (header < 0 || header > 0xffff) {
            throw new IllegalStateException("Unity header is outside the wire range: " + direction + ":" + name);
        }
        return header;
    }
}
