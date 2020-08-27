/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch IO.GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.elements.util.WipAPI;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.ContentType;
import org.eclipse.californium.scandium.dtls.NodeConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.Record;
import org.eclipse.californium.scandium.dtls.SessionCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * DTLS cluster connector.
 * 
 * Forwards foreign cid records to other connectors.
 * 
 * @since 2.5
 */
@WipAPI
public class DtlsClusterConnector extends DTLSConnector {

	public static final long DISCOVER_INTERVAL_MILLIS = 30000;
	public static final long REFRESH_INTERVAL_MILLIS = 10000;
	public static final long EXPIRES_MILLIS = 30000;

	private static final Logger LOGGER = LoggerFactory.getLogger(DtlsClusterConnector.class);

	/**
	 * Datagram offset for messages forwarded to other nodes.
	 */
	private static final int DATAGRAM_OFFSET = 20;
	/**
	 * Type of incoming forwarded messages.
	 */
	private static final byte MAGIC_INCOMING = (byte) 63;
	/**
	 * Type of outgoing forwarded messages.
	 */
	private static final byte MAGIC_OUTGOING = (byte) 62;

	private static final byte MAGIC_ID_PING = (byte) 61;

	private static final byte MAGIC_ID_PONG = (byte) 60;

	private static final byte MAGIC_PING = (byte) 59;

	/**
	 * Node providers for cluster.
	 */
	private final ClusterNodesProvider nodesProvider;

	private final NodesDiscoverer nodesDiscoverer;

	/**
	 * CID generator for this node.
	 */
	private final NodeConnectionIdGenerator nodeCidGenerator;
	/**
	 * Node ID within cluster.
	 */
	private final int nodeId;
	private final DtlsClusterHealth clusterHealth;
	/**
	 * Socket address for cluster internal communication.
	 */
	private volatile InetSocketAddress clusterSocketAddress;
	/**
	 * Datagram socket for cluster internal communication.
	 */
	private volatile DatagramSocket clusterSocket;

	/**
	 * Create dtls connector with cluster support.
	 * 
	 * @param configuration dtls configuration
	 * @param nodes nodes provider
	 */
	public DtlsClusterConnector(DtlsConnectorConfig configuration, ClusterNodesProvider nodes) {
		super(configuration);
		this.nodesProvider = nodes;
		this.nodesDiscoverer = null;
		this.nodeCidGenerator = init();
		this.nodeId = nodeCidGenerator.getNodeId();
		this.clusterHealth = (health instanceof DtlsClusterHealth) ? (DtlsClusterHealth) health : null;
		LOGGER.info("cluster node {} on {}", nodeId, StringUtil.toDisplayString(clusterSocketAddress));
	}

	/**
	 * Create dtls connector with cluster support and session cache.
	 * 
	 * @param configuration dtls configuration
	 * @param nodes nodes provider
	 * @param sessionCache session cache
	 */
	public DtlsClusterConnector(DtlsConnectorConfig configuration, ClusterNodesProvider nodes,
			SessionCache sessionCache) {
		super(configuration, sessionCache);
		this.nodesProvider = nodes;
		this.nodesDiscoverer = null;
		this.nodeCidGenerator = init();
		this.nodeId = nodeCidGenerator.getNodeId();
		this.clusterHealth = (health instanceof DtlsClusterHealth) ? (DtlsClusterHealth) health : null;
		LOGGER.info("cluster node {} on {}", nodeId, StringUtil.toDisplayString(clusterSocketAddress));
	}

	public DtlsClusterConnector(DtlsConnectorConfig configuration, ClusterNodesDiscover nodes) {
		super(configuration);
		this.nodesDiscoverer = new NodesDiscoverer(nodes);
		this.nodesProvider = nodesDiscoverer;
		this.nodeCidGenerator = init();
		this.nodeId = nodeCidGenerator.getNodeId();
		this.clusterSocketAddress = nodes.getDiscoverInterface();
		this.clusterHealth = (health instanceof DtlsClusterHealth) ? (DtlsClusterHealth) health : null;
		LOGGER.info("cluster node {} on {}", nodeId, StringUtil.toDisplayString(clusterSocketAddress));
	}

	public DtlsClusterConnector(DtlsConnectorConfig configuration, ClusterNodesDiscover nodes,
			SessionCache sessionCache) {
		super(configuration, sessionCache);
		this.nodesDiscoverer = new NodesDiscoverer(nodes);
		this.nodesProvider = nodesDiscoverer;
		this.nodeCidGenerator = init();
		this.nodeId = nodeCidGenerator.getNodeId();
		this.clusterSocketAddress = nodes.getDiscoverInterface();
		this.clusterHealth = (health instanceof DtlsClusterHealth) ? (DtlsClusterHealth) health : null;
		LOGGER.info("cluster node {} on {}", nodeId, StringUtil.toDisplayString(clusterSocketAddress));
	}

	/**
	 * Initialize node.
	 * 
	 * @return node's cid generator.
	 * @throws IllegalArgumentException if cid generator is not provided, or the
	 *             cid generator only supports, but doesn't use cids, or the cid
	 *             generator is no {@link NodeConnectionIdGenerator}. Or, if the
	 *             nodes provider doesn't return a address for this node
	 */
	private NodeConnectionIdGenerator init() {
		if (connectionIdGenerator == null) {
			throw new IllegalArgumentException("CID generator missing!");
		} else if (!connectionIdGenerator.useConnectionId()) {
			throw new IllegalArgumentException("CID not used!");
		} else if (!(connectionIdGenerator instanceof NodeConnectionIdGenerator)) {
			throw new IllegalArgumentException("CID generator not supports nodes!");
		}
		NodeConnectionIdGenerator nodeCidGenerator = (NodeConnectionIdGenerator) connectionIdGenerator;
		int nodeId = nodeCidGenerator.getNodeId();
		if (nodesDiscoverer == null) {
			clusterSocketAddress = nodesProvider.getClusterNode(nodeId);
			if (clusterSocketAddress == null) {
				throw new IllegalArgumentException("Local cluster socker address missing for " + nodeId + "!");
			}
		}
		return nodeCidGenerator;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Creates a {@link DtlsClusterHealthLogger}.
	 */
	@Override
	protected DtlsHealth createDefaultHealthHandler(DtlsConnectorConfig configuration) {
		return new DtlsClusterHealthLogger(configuration.getLoggingTag());
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Creates socket and threads for cluster internal communication.
	 */
	@Override
	protected void init(InetSocketAddress bindAddress, DatagramSocket socket, Integer mtu) throws IOException {
		clusterSocket = new DatagramSocket(clusterSocketAddress);
		super.init(bindAddress, socket, mtu);
		int receiverThreadCount = config.getReceiverThreadCount();
		for (int i = 0; i < receiverThreadCount; i++) {
			Worker receiver = new Worker("DTLS-Cluster-" + nodeId + "-Receiver-" + i + "-" + clusterSocketAddress) {

				private final byte[] receiverBuffer = new byte[inboundDatagramBufferSize + DATAGRAM_OFFSET];
				private final DatagramPacket clusterPacket = new DatagramPacket(receiverBuffer, receiverBuffer.length);

				@Override
				public void doWork() throws Exception {
					clusterPacket.setData(receiverBuffer);
					receiveNextDatagramFromClusterNetwork(clusterPacket);
				}
			};
			receiver.setDaemon(true);
			receiver.start();
			receiverThreads.add(receiver);
		}
		if (nodesDiscoverer != null) {
			timer.scheduleAtFixedRate(new Runnable() {

				@Override
				public void run() {
					nodesDiscoverer.refresh(clusterSocket);
				}
			}, 2000, REFRESH_INTERVAL_MILLIS, TimeUnit.MILLISECONDS);
			timer.scheduleAtFixedRate(new Runnable() {

				@Override
				public void run() {
					final DatagramSocket discoverSocket = clusterSocket;
					if (discoverSocket != null && !discoverSocket.isClosed()) {
						nodesDiscoverer.discover(discoverSocket);
					}
				}
			}, 4000, DISCOVER_INTERVAL_MILLIS, TimeUnit.MILLISECONDS);
		}
		LOGGER.info("cluster node {} started {}", nodeId, clusterSocket.getLocalSocketAddress());
	}

	@Override
	public void stop() {
		clusterSocket.close();
		super.stop();
	}

	/**
	 * Receive next cluster internal message.
	 * 
	 * @param clusterPacket cluster internal message
	 * @throws IOException if an io-error occurred.
	 */
	protected void receiveNextDatagramFromClusterNetwork(DatagramPacket clusterPacket) throws IOException {
		clusterPacket.setLength(inboundDatagramBufferSize);

		clusterSocket.receive(clusterPacket);

		final byte type = clusterPacket.getData()[clusterPacket.getOffset()];
		if (type != MAGIC_PING && clusterPacket.getLength() < 5) {
			// nothing to do
			return;
		}
		InetSocketAddress router = (InetSocketAddress) clusterPacket.getSocketAddress();
		if (type == MAGIC_PING || type == MAGIC_ID_PING) {
			if (nodesDiscoverer != null && type == MAGIC_ID_PING) {
				int foreignNodeId = decodePingPong(clusterPacket);
				nodesDiscoverer.update(router, foreignNodeId);
				LOGGER.warn("cluster-node {}: >update node {} to {}", nodeId, foreignNodeId, router);
			}
			// reset packet size
			clusterPacket.setData(clusterPacket.getData());
			encodePingPong(clusterPacket, MAGIC_ID_PONG, nodeId);
			clusterSocket.send(clusterPacket);
		} else if (type == MAGIC_ID_PONG) {
			int foreignNodeId = decodePingPong(clusterPacket);
			if (nodesDiscoverer != null) {
				nodesDiscoverer.update(router, foreignNodeId);
				LOGGER.warn("cluster-node {}: <update node {} to {}", nodeId, foreignNodeId, router);
			}
		} else if (type == MAGIC_INCOMING || type == MAGIC_OUTGOING) {
			DatagramPacket packet = decode(clusterPacket);
			if (packet == null) {
				// nothing to do
				return;
			}
			if (type == MAGIC_INCOMING) {
				LOGGER.info("Cluster {} received forwarded message", nodeId);
				InetSocketAddress source = (InetSocketAddress) packet.getSocketAddress();
				super.processDatagram(packet, new RouterInetSocketAddress(source, router));
				if (clusterHealth != null) {
					clusterHealth.processForwardedMessage();
				}
			} else if (type == MAGIC_OUTGOING) {
				LOGGER.info("Cluster {} received backwarded outgoing message", nodeId);
				super.sendNextDatagramOverNetwork(packet);
				if (clusterHealth != null) {
					clusterHealth.sendBackwardedMessage();
				}
			}
		} else {
			LOGGER.info("Cluster {} received unknown message", nodeId);
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Test for CID records and forward foreign records to other nodes.
	 */
	@Override
	protected void processDatagram(DatagramPacket packet, InetSocketAddress source) {
		int offset = packet.getOffset();
		int length = packet.getLength();
		byte[] data = packet.getData();
		if (data[offset] == ContentType.TLS12_CID.getCode()) {
			if (length > Record.RECORD_HEADER_BYTES) {
				DatagramReader reader = new DatagramReader(data, offset, length);
				ConnectionId cid = Record.readConnectionIdFromReader(reader, connectionIdGenerator);
				if (cid != null) {
					int incomingNodeId = nodeCidGenerator.getNodeId(cid);
					if (nodeId != incomingNodeId) {
						LOGGER.info("Cluster {} received foreign message for {} from {}", nodeId, incomingNodeId,
								source);
						InetSocketAddress clusterNode = nodesProvider.getClusterNode(incomingNodeId);
						if (clusterNode != null) {
							DatagramPacket clusterPacket = encode(packet, MAGIC_INCOMING);
							clusterPacket.setSocketAddress(clusterNode);
							try {
								LOGGER.info("Cluster {} forwards received message from {} to {}, {} bytes", nodeId,
										source, clusterNode, length);
								clusterSocket.send(clusterPacket);
								if (clusterHealth != null) {
									clusterHealth.forwardMessage();
								}
								return;
							} catch (IOException e) {
								LOGGER.info("Cluster send error:", e);
							}
						} else {
							LOGGER.info(
									"Cluster {} received foreign message from {} for unknown node {}, {} bytes, dropping.",
									nodeId, source, incomingNodeId, length);
							if (clusterHealth != null) {
								clusterHealth.dropForwardMessage();
							} else {
								health.receivingRecord(true);
							}
						}
					} else {
						LOGGER.info("Cluster {} received own message from {}, {} bytes", nodeId, source, length);
					}
				} else {
					LOGGER.info("Cluster {} received broken CID message from {}", nodeId, source);
				}
			} else {
				LOGGER.info("Cluster {} received too short CID message from {}", nodeId, source);
			}
		} else {
			LOGGER.info("Cluster {} received no CID message from {}, {} bytes.", nodeId, source, length);
		}
		super.processDatagram(packet, source);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * For {@link RouterInetSocketAddress} destinations, backwards massage to
	 * original receiving connector.
	 */
	@Override
	protected void sendRecord(Record record) throws IOException {
		InetSocketAddress destination = record.getPeerAddress();
		if (destination instanceof RouterInetSocketAddress) {
			InetSocketAddress router = ((RouterInetSocketAddress) destination).getRouter();
			if (nodesProvider.available(router)) {
				byte[] recordBytes = record.toByteArray();
				int length = recordBytes.length;
				byte[] datagramBytes = new byte[length + DATAGRAM_OFFSET];
				System.arraycopy(recordBytes, 0, datagramBytes, DATAGRAM_OFFSET, length);
				DatagramPacket datagram = new DatagramPacket(datagramBytes, DATAGRAM_OFFSET, length,
						record.getPeerAddress());
				LOGGER.info("Cluster {} backwards send message for {} to {}, {} bytes", nodeId, destination, router,
						length);
				DatagramPacket clusterPacket = encode(datagram, MAGIC_OUTGOING);
				clusterPacket.setSocketAddress(router);
				clusterSocket.send(clusterPacket);
				if (clusterHealth != null) {
					clusterHealth.backwardMessage();
				}
			} else {
				if (clusterHealth != null) {
					clusterHealth.dropBackwardMessage();
				} else {
					health.sendingRecord(true);
				}
			}
		} else {
			LOGGER.info("Cluster {} sends message to {}, {} bytes", nodeId, destination, record.size());
			super.sendRecord(record);
		}
	}

	/**
	 * Encode message for cluster internal communication.
	 * 
	 * Add original source address at message head.
	 * 
	 * @param packet received message
	 * @param direction direction of message. Values are {@link #MAGIC_INCOMING}
	 *            or {@link #MAGIC_OUTGOING}
	 * @return encoded message with original source address
	 * @see #decode(DatagramPacket)
	 */
	private DatagramPacket encode(DatagramPacket packet, byte direction) {
		InetAddress source = packet.getAddress();
		byte[] data = packet.getData();
		int offset = packet.getOffset();
		int length = packet.getLength();
		if (offset != DATAGRAM_OFFSET) {
			System.arraycopy(data, offset, data, DATAGRAM_OFFSET, length);
		}
		byte[] address = source.getAddress();
		data[0] = direction;
		data[1] = (byte) address.length;
		data[2] = (byte) packet.getPort();
		data[3] = (byte) (packet.getPort() >> 8);
		System.arraycopy(address, 0, data, 4, address.length);
		packet.setData(data, 0, length + DATAGRAM_OFFSET);
		return packet;
	}

	/**
	 * Decode message for cluster internal communication.
	 * 
	 * @param packet message with original source address encoded at head.
	 * @return message with decoded original source address
	 * @see #encode(DatagramPacket, byte)
	 */
	private DatagramPacket decode(DatagramPacket packet) {
		byte[] data = packet.getData();
		int offset = packet.getOffset();
		int length = packet.getLength();
		if (offset == 0) {
			int addressLength = data[1] & 0xff;
			int port = (data[2] & 0xff) | ((data[3] & 0xff) << 8);
			byte[] address = Arrays.copyOfRange(data, 4, addressLength + 4);
			try {
				InetAddress iaddr = InetAddress.getByAddress(address);
				packet.setAddress(iaddr);
				packet.setPort(port);
				packet.setData(data, DATAGRAM_OFFSET, length - DATAGRAM_OFFSET);
				return packet;
			} catch (UnknownHostException e) {
			}
		} else {
			LOGGER.warn("Packet misformed!");
		}
		return null;
	}

	private static int decodePingPong(DatagramPacket packet) {
		byte[] data = packet.getData();
		int offset = packet.getOffset();
		int nodeId = data[offset + 1] & 0xff;
		nodeId |= (data[offset + 2] & 0xff) << 8;
		nodeId |= (data[offset + 3] & 0xff) << 16;
		nodeId |= (data[offset + 4] & 0xff) << 24;
		return nodeId;
	}

	private static void encodePingPong(DatagramPacket packet, byte type, int nodeId) {
		byte[] data = packet.getData();
		int offset = packet.getOffset();
		data[offset] = type;
		data[offset + 1] = (byte) (nodeId);
		data[offset + 2] = (byte) (nodeId >> 8);
		data[offset + 3] = (byte) (nodeId >> 16);
		data[offset + 4] = (byte) (nodeId >> 24);
		packet.setLength(5);
	}

	/**
	 * Cluster nodes provider. Maintaining internal addresses of nodes.
	 */
	public static interface ClusterNodesProvider {

		/**
		 * Get address for node.
		 * 
		 * @param nodeId node id of node
		 * @return internal address of node. {@code null}, if not available.
		 */
		InetSocketAddress getClusterNode(int nodeId);

		/**
		 * Check, if address to backward message is still available.
		 * 
		 * @param destinationConnector address of destination connector.
		 * @return {@code true}, if destination is still available,
		 *         {@code false}, if not.
		 */
		boolean available(InetSocketAddress destinationConnector);
	}

	public static interface ClusterNodesDiscover {

		InetSocketAddress getDiscoverInterface();

		List<InetSocketAddress> getClusterNodesDiscoverScope();

	}

	private class NodesDiscoverer implements ClusterNodesProvider {

		private final byte[] discoverBuffer = new byte[128];
		private final DatagramPacket discoverPacket = new DatagramPacket(discoverBuffer, discoverBuffer.length);
		private final ClusterNodesDiscover discoverScope;
		private final ConcurrentMap<Integer, Node> nodesById = new ConcurrentHashMap<>();
		private final ConcurrentMap<InetSocketAddress, Node> nodesByAddress = new ConcurrentHashMap<>();

		private NodesDiscoverer(ClusterNodesDiscover discoverScope) {
			this.discoverScope = discoverScope;
		}

		@Override
		public InetSocketAddress getClusterNode(int nodeId) {
			Node node = nodesById.get(nodeId);
			if (node != null) {
				return node.address;
			} else {
				return null;
			}
		}

		@Override
		public boolean available(InetSocketAddress destinationConnector) {
			return nodesByAddress.containsKey(destinationConnector);
		}

		public synchronized void update(InetSocketAddress address, int nodeId) {
			Node iNode = nodesById.get(nodeId);
			if (iNode == null) {
				iNode = new Node(nodeId, address);
				nodesById.put(nodeId, iNode);
			} else {
				iNode.update(address);
			}
			Node aNode = nodesByAddress.put(address, iNode);
			if (aNode != null && aNode != iNode) {
				nodesById.remove(nodeId, aNode);
			}
		}

		public synchronized void remove(Node node) {
			nodesById.remove(node.nodeId, node);
			nodesByAddress.remove(node.address, node);
		}

		public void refresh(DatagramSocket clusterSocket) {
			encodePingPong(discoverPacket, MAGIC_ID_PING, nodeId);
			long now = ClockUtil.nanoRealtime();
			long expireTimeNanos = now - TimeUnit.MILLISECONDS.toNanos(EXPIRES_MILLIS);
			long freshTimeNanos = now - TimeUnit.MILLISECONDS.toNanos(REFRESH_INTERVAL_MILLIS / 2);
			for (Node node : nodesById.values()) {
				if (node.isBefore(expireTimeNanos)) {
					remove(node);
				} else if (node.isBefore(freshTimeNanos)) {
					if (clusterSocket != null && !clusterSocket.isClosed()) {
						discoverPacket.setSocketAddress(node.address);
						try {
							clusterSocket.send(discoverPacket);
							LOGGER.warn("cluster-node {}: refresh node {} at {}", nodeId, node.nodeId, node.address);
						} catch (IOException e) {
							LOGGER.debug("sending cluster ping failed!", e);
						}
					}
				}
			}
		}

		public void discover(DatagramSocket clusterSocket) {
			encodePingPong(discoverPacket, MAGIC_ID_PING, nodeId);
			InetSocketAddress own = discoverScope.getDiscoverInterface();
			List<InetSocketAddress> scope = discoverScope.getClusterNodesDiscoverScope();
			for (InetSocketAddress node : scope) {
				if (!own.equals(node) && !nodesByAddress.containsKey(node)) {
					discoverPacket.setSocketAddress(node);
					try {
						clusterSocket.send(discoverPacket);
						LOGGER.warn("cluster-node {}: discover {}", nodeId, node);
					} catch (IOException e) {
						LOGGER.debug("sending cluster ping failed!", e);
					}
				}
			}
		}
	}

	private static class Node {

		private final int nodeId;
		private InetSocketAddress address;
		private long time;

		private Node(int nodeId, InetSocketAddress address) {
			this.nodeId = nodeId;
			update(address);
		}

		private synchronized void update(InetSocketAddress address) {
			this.address = address;
			this.time = ClockUtil.nanoRealtime();
		}

		private synchronized boolean isBefore(long timeNanos) {
			return timeNanos - time > 0;
		}
	}
}
