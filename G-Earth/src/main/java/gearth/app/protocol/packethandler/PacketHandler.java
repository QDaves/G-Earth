package gearth.app.protocol.packethandler;

import gearth.misc.listenerpattern.Observable;
import gearth.protocol.HMessage;
import gearth.app.protocol.TrafficListener;
import gearth.app.services.extension_handler.ExtensionHandler;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;

public abstract class PacketHandler {

    private final ExtensionHandler extensionHandler;
    private final Observable<TrafficListener>[] trafficObservables; //get notified on packet send
    protected volatile int currentIndex = 0;
    protected final Object sendLock = new Object();
    protected final Object flushLock = new Object();

    protected PacketHandler(ExtensionHandler extensionHandler, Observable<TrafficListener>[] trafficObservables) {
        this.extensionHandler = extensionHandler;
        this.trafficObservables = trafficObservables;
    }

    public abstract boolean sendToStream(byte[] buffer);

    public abstract void act(byte[] buffer) throws IOException;

    protected void notifyListeners(int i, HMessage message) {
        trafficObservables[i].fireEvent(trafficListener -> {
            message.getPacket().resetReadIndex();
            trafficListener.onCapture(message);
        });
        message.getPacket().resetReadIndex();
    }

    protected void awaitListeners(HMessage message, PacketSender packetSender) {
        manipulate(message).thenAccept(message2 -> {
            if (!message2.isBlocked()) {
                packetSender.send(message2);
            }
        });
    }

    protected CompletableFuture<HMessage> manipulate(HMessage message) {
        notifyListeners(TrafficListener.BEFORE_MODIFICATION, message);
        notifyListeners(TrafficListener.MODIFICATION, message);
        CompletableFuture<HMessage> result = new CompletableFuture<>();
        extensionHandler.handle(message, message2 -> {
            notifyListeners(TrafficListener.AFTER_MODIFICATION, message2);
            result.complete(message2);
        });
        return result;
    }

}
