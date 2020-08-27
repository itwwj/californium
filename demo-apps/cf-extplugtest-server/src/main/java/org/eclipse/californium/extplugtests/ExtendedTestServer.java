/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 *    Achim Kraus (Bosch Software Innovations GmbH) - use special properties file
 *                                                    for configuration
 *    Achim Kraus (Bosch Software Innovations GmbH) - add benchmark
 *    Achim Kraus (Bosch Software Innovations GmbH) - use executors util.
 ******************************************************************************/
package org.eclipse.californium.extplugtests;

import java.io.File;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.lang.management.OperatingSystemMXBean;
import java.lang.management.ThreadMXBean;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointContextMatcherFactory.MatcherMode;
import org.eclipse.californium.core.network.EndpointObserver;
import org.eclipse.californium.core.network.MessagePostProcessInterceptors;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.core.network.interceptors.AnonymizedOriginTracer;
import org.eclipse.californium.core.network.interceptors.HealthStatisticLogger;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.elements.PrincipalEndpointContextMatcher;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.NamedThreadFactory;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.extplugtests.resources.Benchmark;
import org.eclipse.californium.extplugtests.resources.RequestStatistic;
import org.eclipse.californium.extplugtests.resources.ReverseObserve;
import org.eclipse.californium.extplugtests.resources.ReverseRequest;
import org.eclipse.californium.plugtests.AbstractTestServer;
import org.eclipse.californium.plugtests.PlugtestServer;
import org.eclipse.californium.plugtests.PlugtestServer.BaseConfig;
import org.eclipse.californium.plugtests.resources.MyIp;
import org.eclipse.californium.scandium.DtlsClusterConnector;
import org.eclipse.californium.scandium.DtlsClusterConnector.ClusterNodesDiscover;
import org.eclipse.californium.scandium.MdcConnectionListener;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.MultiNodeConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.AsyncAdvancedPskStore;
import org.eclipse.californium.scandium.dtls.x509.AsyncNewAdvancedCertificateVerifier;
import org.eclipse.californium.unixhealth.NetStatLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.ITypeConverter;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.ParseResult;

/**
 * Extended test server.
 * 
 * Setup for larger blocks than the plugtest server and provides the request
 * statistic resource.
 */
public class ExtendedTestServer extends AbstractTestServer {

	private static final Logger STATISTIC_LOGGER = LoggerFactory
			.getLogger("org.eclipse.californium.extplugtests.statistics");

	private static final File CONFIG_FILE = new File("CaliforniumReceivetest.properties");
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Receivetest Server";
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 8192;
	private static final int DEFAULT_BLOCK_SIZE = 1024;

	private static NetworkConfigDefaultHandler DEFAULTS = new NetworkConfigDefaultHandler() {

		@Override
		public void applyDefaults(NetworkConfig config) {
			// start on alternative port, 5783 and 5784
			config.setInt(Keys.COAP_PORT, config.getInt(Keys.COAP_PORT) + 100);
			config.setInt(Keys.COAP_SECURE_PORT, config.getInt(Keys.COAP_SECURE_PORT) + 100);
			config.setInt(Keys.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.setInt(Keys.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.setInt(Keys.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
			config.setInt(Keys.PEERS_MARK_AND_SWEEP_MESSAGES, 16);
			config.setString(Keys.DEDUPLICATOR, Keys.DEDUPLICATOR_PEERS_MARK_AND_SWEEP);
			config.setInt(Keys.MAX_ACTIVE_PEERS, 2000000);
			config.setInt(Keys.DTLS_AUTO_RESUME_TIMEOUT, 0);
			config.setInt(Keys.DTLS_CONNECTION_ID_LENGTH, 6);
			config.setInt(Keys.DTLS_CONNECTION_ID_NODE_ID, 1);
			config.setInt(Keys.MAX_PEER_INACTIVITY_PERIOD, 60); // 24h
			config.setInt(Keys.TCP_CONNECTION_IDLE_TIMEOUT, 60 * 60 * 12); // 12h
			config.setInt(Keys.TLS_HANDSHAKE_TIMEOUT, 60 * 1000); // 60s
			config.setInt(Keys.SECURE_SESSION_TIMEOUT, 60 * 60 * 24); // 24h
			config.setInt(Keys.HEALTH_STATUS_INTERVAL, 60); // 60s
			config.setInt(Keys.UDP_CONNECTOR_RECEIVE_BUFFER, 0);
			config.setInt(Keys.UDP_CONNECTOR_SEND_BUFFER, 0);
			config.setInt(KEY_DTLS_HANDSHAKE_RESULT_DELAY, 500);
			int processors = Runtime.getRuntime().availableProcessors();
			config.setInt(Keys.NETWORK_STAGE_RECEIVER_THREAD_COUNT, processors > 3 ? 2 : 1);
			config.setInt(Keys.NETWORK_STAGE_SENDER_THREAD_COUNT, processors);
		}

	};

	@Command(name = "ExtendedTestServer", version = "(c) 2017-2020, Bosch.IO GmbH and others.")
	private static class Config extends PlugtestServer.BaseConfig {

		@Option(names = "--no-plugtest", negatable = true, description = "enable plugtest server.")
		public boolean plugtest = true;

		@Option(names = "--benchmark", negatable = true, description = "enable benchmark resource.")
		public boolean benchmark;

		@Option(names = "--dtls-cluster", split = ",", description = "enable DTLS-cluster mode.")
		public List<Cluster> dtlsClusterNodes;

		@Option(names = "--dtls-cluster-group", split = ",", description = "enable dynamic DTLS-cluster mode.")
		public List<InetSocketAddress> dtlsClusterGroup;

		public void register(CommandLine cmd) {
			cmd.registerConverter(Cluster.class, clusterDefinition);
			cmd.registerConverter(InetSocketAddress.class, addressDefinition);
		}

	}

	private static final Config config = new Config();

	public static void main(String[] args) {
		CommandLine cmd = new CommandLine(config);
		config.register(cmd);
		try {
			ParseResult result = cmd.parseArgs(args);
			if (result.isVersionHelpRequested()) {
				String version = StringUtil.CALIFORNIUM_VERSION == null ? "" : StringUtil.CALIFORNIUM_VERSION;
				System.out.println("\nCalifornium (Cf) " + cmd.getCommandName() + " " + version);
				cmd.printVersionHelp(System.out);
				System.out.println();
			}
			if (result.isUsageHelpRequested()) {
				cmd.usage(System.out);
				return;
			}
		} catch (ParameterException ex) {
			System.err.println(ex.getMessage());
			System.err.println();
			cmd.usage(System.err);
			System.exit(-1);
		}

		STATISTIC_LOGGER.error("start!");
		startManagamentStatistic();
		if (config.dtlsClusterNodes != null) {
			config.onlyDtls = true;
			if (config.dtlsClusterGroup != null) {
				System.out.println("dynamic dtls-cluster!");
			} else {
				System.out.println("static dtls-cluster!");
			}
		} else if (config.plugtest) {
			// start standard plugtest server
			PlugtestServer.start(config);
		}

		NetworkConfig netConfig = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		NetworkConfig udpConfig = new NetworkConfig(netConfig);
		udpConfig.setInt(Keys.MAX_MESSAGE_SIZE, 64);
		udpConfig.setInt(Keys.PREFERRED_BLOCK_SIZE, 64);
		Map<Select, NetworkConfig> protocolConfig = new HashMap<>();
		protocolConfig.put(new Select(Protocol.UDP, InterfaceType.EXTERNAL), udpConfig);

		// create server
		try {
			List<Protocol> protocols;

			if (config.onlyDtls) {
				protocols = Arrays.asList(Protocol.DTLS);
			} else if (config.tcp) {
				protocols = Arrays.asList(Protocol.UDP, Protocol.DTLS, Protocol.TCP, Protocol.TLS);
			} else {
				protocols = Arrays.asList(Protocol.UDP, Protocol.DTLS);
			}
			List<InterfaceType> types = new ArrayList<InterfaceType>();
			if (config.external) {
				types.add(InterfaceType.EXTERNAL);
			}
			if (config.loopback) {
				types.add(InterfaceType.LOCAL);
			}
			int s = types.size();
			if (s == 0) {
				System.err.println("Either --loopback or --external must be enabled!");
				System.exit(1);
			}
			if (config.ipv6) {
				types.add(InterfaceType.IPV6);
			}
			if (config.ipv4) {
				types.add(InterfaceType.IPV4);
			}
			if (s == types.size()) {
				System.err.println("Either --ipv4 or --ipv6 must be enabled!");
			}
			String pattern = config.interfacePatterns != null && !config.interfacePatterns.isEmpty()
					? config.interfacePatterns.get(0)
					: null;

			ScheduledExecutorService executor = ExecutorsUtil.newScheduledThreadPool(//
					netConfig.getInt(NetworkConfig.Keys.PROTOCOL_STAGE_THREAD_COUNT), //
					new NamedThreadFactory("CoapServer(main)#")); //$NON-NLS-1$
			ScheduledExecutorService secondaryExecutor = ExecutorsUtil
					.newDefaultSecondaryScheduler("CoapServer(secondary)#");

			ExtendedTestServer server = new ExtendedTestServer(netConfig, protocolConfig, !config.benchmark);
			server.setExecutors(executor, secondaryExecutor, false);
			server.add(new ReverseRequest(netConfig, executor));
			ReverseObserve reverseObserver = new ReverseObserve(netConfig, executor);
			server.add(reverseObserver);

			if (config.dtlsClusterNodes != null) {
				ClusterGroup group = null;
				DtlsClusterConnector.ClusterNodesProvider nodes = null;
				if (config.dtlsClusterGroup == null) {
					nodes = new DtlsClusterConnector.ClusterNodesProvider() {

						@Override
						public InetSocketAddress getClusterNode(int nodeId) {
							for (Cluster node : config.dtlsClusterNodes) {
								if (node.nodeid == nodeId) {
									return node.cluster;
								}
							}
							return null;
						}

						@Override
						public boolean available(InetSocketAddress destinationConnector) {
							return true;
						}
					};
				}
				for (Cluster cluster : config.dtlsClusterNodes) {
					if (config.dtlsClusterGroup != null) {
						group = new ClusterGroup(config.dtlsClusterGroup, cluster.cluster);
					}
					server.addClusterEndpoint(config, cluster, secondaryExecutor, nodes, group);
				}
			} else {
				server.addEndpoints(pattern, types, protocols, config);
			}
			for (Endpoint ep : server.getEndpoints()) {
				ep.addNotificationListener(reverseObserver);
			}
			server.start();

			// add special interceptor for message traces
			for (Endpoint ep : server.getEndpoints()) {
				URI uri = ep.getUri();
				if (!config.benchmark) {
					// Anonymized IoT metrics for validation.
					ep.addInterceptor(new AnonymizedOriginTracer(uri.getPort() + "-" + uri.getScheme()));
					ep.addInterceptor(new MessageTracer());
				}
				if (ep instanceof MessagePostProcessInterceptors) {
					if (((MessagePostProcessInterceptors) ep).getPostProcessInterceptors().isEmpty()) {
						int interval = ep.getConfig().getInt(NetworkConfig.Keys.HEALTH_STATUS_INTERVAL);
						final HealthStatisticLogger healthLogger = new HealthStatisticLogger(uri.toASCIIString(),
								!CoAP.isTcpScheme(uri.getScheme()), interval, executor);
						if (healthLogger.isEnabled()) {
							((MessagePostProcessInterceptors) ep).addPostProcessInterceptor(healthLogger);
							ep.addObserver(new EndpointObserver() {

								@Override
								public void stopped(Endpoint endpoint) {
									healthLogger.stop();
								}

								@Override
								public void started(Endpoint endpoint) {
									healthLogger.start();
								}

								@Override
								public void destroyed(Endpoint endpoint) {
									healthLogger.stop();
								}
							});
							healthLogger.start();
						}
					}
				}
			}

			if (!config.benchmark) {
				System.out.println(ExtendedTestServer.class.getSimpleName() + " without benchmark started ...");
			} else {
				NetStatLogger netstat = new NetStatLogger("udp");
				Runtime runtime = Runtime.getRuntime();
				long max = runtime.maxMemory();
				StringBuilder builder = new StringBuilder(ExtendedTestServer.class.getSimpleName());
				if (StringUtil.CALIFORNIUM_VERSION != null) {
					builder.append(", version ").append(StringUtil.CALIFORNIUM_VERSION);
				}
				builder.append(", ").append(max / (1024 * 1024)).append("MB heap.");
				System.out.println(builder);
				long lastGcCount = 0;
				for (;;) {
					try {
						Thread.sleep(15000);
					} catch (InterruptedException e) {
						break;
					}
					long used = runtime.totalMemory() - runtime.freeMemory();
					int fill = (int) ((used * 100L) / max);
					if (fill > 80) {
						System.out.println("Maxium heap size: " + max / (1024 * 1024) + "M " + fill + "% used.");
						System.out.println("Heap may exceed! Enlarge the maxium heap size.");
						System.out.println("Or consider to reduce the value of " + Keys.EXCHANGE_LIFETIME);
						System.out.println("in \"" + CONFIG_FILE + "\" or set");
						System.out.println(Keys.DEDUPLICATOR + " to " + Keys.NO_DEDUPLICATOR + " there.");
					}
					long gcCount = 0;
					for (GarbageCollectorMXBean gcMXBean : ManagementFactory.getGarbageCollectorMXBeans()) {
						long count = gcMXBean.getCollectionCount();
						if (0 < count) {
							gcCount += count;
						}
					}
					if (lastGcCount < gcCount) {
						printManagamentStatistic();
						lastGcCount = gcCount;
						netstat.dump();
					}
				}
			}

		} catch (Exception e) {

			System.err.printf("Failed to create " + ExtendedTestServer.class.getSimpleName() + ": %s\n",
					e.getMessage());
			e.printStackTrace(System.err);
			System.err.println("Exiting");
			System.exit(PlugtestServer.ERR_INIT_FAILED);
		}

	}

	public ExtendedTestServer(NetworkConfig config, Map<Select, NetworkConfig> protocolConfig, boolean noBenchmark)
			throws SocketException {
		super(config, protocolConfig);
		int maxResourceSize = config.getInt(Keys.MAX_RESOURCE_BODY_SIZE);
		// add resources to the server
		add(new RequestStatistic());
		add(new Benchmark(noBenchmark, maxResourceSize));
		add(new MyIp(MyIp.RESOURCE_NAME, true));
	}

	private static void startManagamentStatistic() {
		ThreadMXBean mxBean = ManagementFactory.getThreadMXBean();
		if (mxBean.isThreadCpuTimeSupported() && !mxBean.isThreadCpuTimeEnabled()) {
			mxBean.setThreadCpuTimeEnabled(true);
		}
	}

	private static void printManagamentStatistic() {
		OperatingSystemMXBean osMxBean = ManagementFactory.getOperatingSystemMXBean();
		int processors = osMxBean.getAvailableProcessors();
		Logger logger = STATISTIC_LOGGER;
		logger.info("{} processors", processors);
		ThreadMXBean threadMxBean = ManagementFactory.getThreadMXBean();
		if (threadMxBean.isThreadCpuTimeSupported() && threadMxBean.isThreadCpuTimeEnabled()) {
			long alltime = 0;
			long[] ids = threadMxBean.getAllThreadIds();
			for (long id : ids) {
				long time = threadMxBean.getThreadCpuTime(id);
				if (0 < time) {
					alltime += time;
				}
			}
			long pTime = alltime / processors;
			logger.info("cpu-time: {} ms (per-processor: {} ms)", TimeUnit.NANOSECONDS.toMillis(alltime),
					TimeUnit.NANOSECONDS.toMillis(pTime));
		}
		long gcCount = 0;
		long gcTime = 0;
		for (GarbageCollectorMXBean gcMxBean : ManagementFactory.getGarbageCollectorMXBeans()) {
			long count = gcMxBean.getCollectionCount();
			if (0 < count) {
				gcCount += count;
			}
			long time = gcMxBean.getCollectionTime();
			if (0 < time) {
				gcTime += time;
			}
		}
		logger.info("gc: {} ms, {} calls", gcTime, gcCount);
		double loadAverage = osMxBean.getSystemLoadAverage();
		if (!(loadAverage < 0.0d)) {
			logger.info("average load: {}", String.format("%.2f", loadAverage));
		}
	}

	private void addClusterEndpoint(BaseConfig cliConfig, Cluster cluster, ScheduledExecutorService secondaryExecutor,
			DtlsClusterConnector.ClusterNodesProvider nodesProvider,
			DtlsClusterConnector.ClusterNodesDiscover nodesDiscoverer) {
		if (nodesDiscoverer == null ^ nodesProvider != null) {
			throw new IllegalArgumentException("either nodes-provider or -dicoverer is required!");
		}
		NetworkConfig netConfig = getConfig();
		Integer cidLength = netConfig.getOptInteger(Keys.DTLS_CONNECTION_ID_LENGTH);
		if (cidLength == null || cidLength < 6) {
			throw new IllegalArgumentException("cid length must be at least 6 for cluster!");
		}
		initCredentials();
		int retransmissionTimeout = netConfig.getInt(Keys.ACK_TIMEOUT);
		int staleTimeout = netConfig.getInt(Keys.MAX_PEER_INACTIVITY_PERIOD);
		int dtlsThreads = netConfig.getInt(Keys.NETWORK_STAGE_SENDER_THREAD_COUNT);
		int dtlsReceiverThreads = netConfig.getInt(Keys.NETWORK_STAGE_RECEIVER_THREAD_COUNT);
		int maxPeers = netConfig.getInt(Keys.MAX_ACTIVE_PEERS);
		int handshakeResultDelay = netConfig.getInt(KEY_DTLS_HANDSHAKE_RESULT_DELAY, 0);
		Integer healthStatusInterval = netConfig.getOptInteger(Keys.HEALTH_STATUS_INTERVAL); // seconds
		Integer recvBufferSize = netConfig.getOptInteger(Keys.UDP_CONNECTOR_RECEIVE_BUFFER);
		Integer sendBufferSize = netConfig.getOptInteger(Keys.UDP_CONNECTOR_SEND_BUFFER);
		DtlsConnectorConfig.Builder dtlsConfigBuilder = new DtlsConnectorConfig.Builder();
		dtlsConfigBuilder.setConnectionIdGenerator(new MultiNodeConnectionIdGenerator(cluster.nodeid, cidLength));
		AsyncAdvancedPskStore asyncPskStore = new AsyncAdvancedPskStore(new PlugPskStore());
		asyncPskStore.setDelay(handshakeResultDelay);
		dtlsConfigBuilder.setAdvancedPskStore(asyncPskStore);
		dtlsConfigBuilder.setAddress(cluster.dtls);
		dtlsConfigBuilder.setSupportedCipherSuites(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
				CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
		dtlsConfigBuilder.setIdentity(serverCredentials.getPrivateKey(), serverCredentials.getCertificateChain(),
				CertificateType.RAW_PUBLIC_KEY, CertificateType.X_509);
		AsyncNewAdvancedCertificateVerifier.Builder verifierBuilder = AsyncNewAdvancedCertificateVerifier.builder();
		if (cliConfig.trustall) {
			verifierBuilder.setTrustAllCertificates();
		} else {
			verifierBuilder.setTrustedCertificates(trustedCertificates);
		}
		verifierBuilder.setTrustAllRPKs();
		AsyncNewAdvancedCertificateVerifier verifier = verifierBuilder.build();
		verifier.setDelay(handshakeResultDelay);
		dtlsConfigBuilder.setAdvancedCertificateVerifier(verifier);
		dtlsConfigBuilder.setMaxConnections(maxPeers);
		dtlsConfigBuilder.setStaleConnectionThreshold(staleTimeout);
		dtlsConfigBuilder.setConnectionThreadCount(dtlsThreads);
		dtlsConfigBuilder.setReceiverThreadCount(dtlsReceiverThreads);
		dtlsConfigBuilder.setHealthStatusInterval(healthStatusInterval);
		dtlsConfigBuilder.setSocketReceiveBufferSize(recvBufferSize);
		dtlsConfigBuilder.setSocketSendBufferSize(sendBufferSize);
		dtlsConfigBuilder.setRetransmissionTimeout(retransmissionTimeout);
		dtlsConfigBuilder.setConnectionListener(new MdcConnectionListener());
		dtlsConfigBuilder.setCidUpdateAddressOnNewerRecordFilter(true);
		dtlsConfigBuilder.setLoggingTag("node-" + cluster.nodeid);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		if (nodesDiscoverer != null) {
			builder.setConnector(new DtlsClusterConnector(dtlsConfigBuilder.build(), nodesDiscoverer));
		} else if (nodesProvider != null) {
			builder.setConnector(new DtlsClusterConnector(dtlsConfigBuilder.build(), nodesProvider));
		}
		if (MatcherMode.PRINCIPAL.name().equals(netConfig.getString(Keys.RESPONSE_MATCHING))) {
			builder.setEndpointContextMatcher(new PrincipalEndpointContextMatcher(true));
		}
		builder.setNetworkConfig(netConfig);
		CoapEndpoint endpoint = builder.build();
		if (healthStatusInterval != null && endpoint instanceof MessagePostProcessInterceptors) {
			String tag = CoAP.COAP_SECURE_URI_SCHEME;
			tag += "-" + cluster.nodeid;
			final HealthStatisticLogger healthLogger = new HealthStatisticLogger(tag, true, healthStatusInterval,
					secondaryExecutor);
			if (healthLogger.isEnabled()) {
				((MessagePostProcessInterceptors) endpoint).addPostProcessInterceptor(healthLogger);
				endpoint.addObserver(new EndpointObserver() {

					@Override
					public void stopped(Endpoint endpoint) {
						healthLogger.stop();
					}

					@Override
					public void started(Endpoint endpoint) {
						healthLogger.start();
					}

					@Override
					public void destroyed(Endpoint endpoint) {
						healthLogger.stop();
					}
				});
				healthLogger.start();
			}
		}
		addEndpoint(endpoint);
		InterfaceType interfaceType = cluster.dtls.getAddress().isLoopbackAddress() ? InterfaceType.LOCAL
				: InterfaceType.EXTERNAL;
		print(endpoint, interfaceType);
	}

	private static class ClusterGroup implements ClusterNodesDiscover {

		private final InetSocketAddress discoverInterface;
		private final List<InetSocketAddress> group;

		private ClusterGroup(List<InetSocketAddress> group, InetSocketAddress discoverInterface) {
			this.group = group;
			this.discoverInterface = discoverInterface;
		}

		@Override
		public InetSocketAddress getDiscoverInterface() {
			return discoverInterface;
		}

		@Override
		public List<InetSocketAddress> getClusterNodesDiscoverScope() {
			return group;
		}
	}

	private static class Cluster {

		final InetSocketAddress dtls;
		final InetSocketAddress cluster;
		final int nodeid;

		private Cluster(String[] args) throws Exception {
			if (args.length != 3) {
				throw new IllegalArgumentException(
						"a cluster definution must contain 3 parts, <dtls-intf>;<mgmt-intf>;nodeid");
			}
			dtls = addressDefinition.convert(args[0]);
			cluster = addressDefinition.convert(args[1]);
			nodeid = Integer.parseInt(args[2]);
		}
	}

	private static ITypeConverter<Cluster> clusterDefinition = new ITypeConverter<Cluster>() {

		@Override
		public Cluster convert(String value) throws Exception {
			return new Cluster(value.split(";"));
		}
	};

	private static ITypeConverter<InetSocketAddress> addressDefinition = new ITypeConverter<InetSocketAddress>() {

		@Override
		public InetSocketAddress convert(String value) throws Exception {
			if (value.startsWith(":")) {
				// port only => any local address
				int port = Integer.parseInt(value.substring(1));
				System.out.println(value + " => <any>:" + port);
				return new InetSocketAddress(port);
			} else {
				// use dummy schema
				URI uri = new URI("cluster://" + value);
				String host = uri.getHost();
				int port = uri.getPort();
				System.out.println(value + " => " + host + ":" + port);
				return new InetSocketAddress(host, port);
			}
		}

	};
}
