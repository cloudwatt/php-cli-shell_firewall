<?php
	require_once(__DIR__ . '/abstract.php');
	require_once(__DIR__ . '/shell/firewall.php');
	require_once(__DIR__ . '/shell/ipam.php');
	require_once(__DIR__ . '/../firewall/abstract.php');
	require_once(__DIR__ . '/../firewall/sites.php');
	require_once(__DIR__ . '/../firewall/api/abstract.php');
	require_once(__DIR__ . '/../firewall/api/site.php');
	require_once(__DIR__ . '/../firewall/api/address.php');
	require_once(__DIR__ . '/../firewall/api/host.php');
	require_once(__DIR__ . '/../firewall/api/subnet.php');
	require_once(__DIR__ . '/../firewall/api/network.php');
	require_once(__DIR__ . '/../firewall/api/protocol.php');
	require_once(__DIR__ . '/../firewall/api/rule.php');
	require_once(__DIR__ . '/../firewall/template/abstract.php');
	require_once(__DIR__ . '/../firewall/template/junos.php');
	require_once(__DIR__ . '/../firewall/template/junos/set.php');
	require_once(__DIR__ . '/../classes/rest.php');
	require_once(__DIR__ . '/../ipam/abstract.php');
	require_once(__DIR__ . '/../ipam/api/abstract.php');
	require_once(__DIR__ . '/../ipam/api/subnet/abstract.php');
	require_once(__DIR__ . '/../ipam/api/subnet.php');
	require_once(__DIR__ . '/../ipam/api/address.php');

	class IPAM extends IPAM_Abstract {}
	class FIREWALL extends FIREWALL_Abstract {}

	class SHELL extends Shell_Abstract {}

	class Service_Firewall extends Service_Abstract
	{
		const SHELL_HISTORY_FILENAME = '.firewall.history';

		protected $_IPAM;

		protected $_Firewall_Sites = null;

		protected $_commands = array(
			'help', 'history',
			'ls', 'll', 'find', 'exit', 'quit',
			'show' => array(
				'site', 'host', 'subnet', 'network', 'rule', 
				'sites', 'hosts', 'subnets', 'networks', 'rules', 
			),
			'create' => array(
				'host',
				'subnet',
				'network',
				'rule',
			),
			'fullmesh',
			'site',
			'action',
			'source' => array('host', 'subnet', 'network'),
			'destination' => array('host', 'subnet', 'network'),
			'protocol',
			'description',
			'check',
			'reset' => array('source', 'destination', 'protocol'),
			'modify' => array('host', 'subnet', 'network', 'rule'),
			'remove' => array('site', 'host', 'subnet', 'network', 'rule'),
			'clear' => array('sites', 'hosts', 'subnets', 'networks', 'rules'),
			//'export' => array('configuration', 'hosts', 'subnets', 'networks', 'rules'),	// @todo a coder
			'export' => array('configuration'),
			'load', 'save',
			'firewall',
		);

		/**
		  * Arguments ne commencant pas par - mais étant dans le flow de la commande
		  *
		  * ls mon/chemin/a/lister
		  * cd mon/chemin/ou/aller
		  * find ou/lancer/ma/recherche
		  */
		protected $_inlineArgCmds = array(
			'ls' => "#^[0-9a-z\-_.]+$#i",
			'll' => "#^[0-9a-z\-_.]+$#i",
			'find' => array(
				0 => "#^\.$#i",
				1 => array('all', 'host', 'subnet', 'network', 'rule'),
				2 => "#^\"?([a-z0-9\-_.:* /\#]+)\"?$#i"),
			'show host' => "#^[0-9a-z\-_.:]+$#i",
			'show subnet' => "#^[0-9a-z\-_.:]+$#i",
			'show network' => "#^[0-9a-z\-_.:]+$#i",
			'show rule' => "#^[0-9]+$#i",
			'create host' => array(0 => '#^[0-9a-z\-_.]+$#i',
				1 => '#^(([0-9]{1,3}\.){3}[0-9]{1,3})|([a-f0-9:]+)$#i',
				2 => '#^(([0-9]{1,3}\.){3}[0-9]{1,3})|([a-f0-9:]+)$#i'
			),		// IPv4/IPv6
			'create subnet' => array(0 => '#^[0-9a-z\-_.]+$#i',
				1 => '#^(([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2})|([a-f0-9:]+/[0-9]{1,3})$#i',
				2 => '#^(([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2})|([a-f0-9:]+/[0-9]{1,3})$#i'
			),		// IPv4/IPv6
			'create network' => array(0 => '#^[0-9a-z\-_.]+$#i',
				1 => '#^(([0-9]{1,3}\.){3}[0-9]{1,3}-[0-9]{1,3}\.){3}[0-9]{1,3})|([a-f0-9:]+-[a-f0-9:]+)$#i',
				2 => '#^(([0-9]{1,3}\.){3}[0-9]{1,3}-[0-9]{1,3}\.){3}[0-9]{1,3})|([a-f0-9:]+-[a-f0-9:]+)$#i'
			),		// IPv4/IPv6
			'create rule' => array(0 => array('monosite', 'failover')),
			'fullmesh' => array(0 => array('enable', 'en', 'disable', 'dis')),
			'action' => array(0 => array('permit', 'deny')),
			'source host' => "#^[0-9a-z\-_.:]+$#i",
			'source subnet' => "#^[0-9a-z\-_.:]+$#i",
			'source network' => "#^[0-9a-z\-_.:]+$#i",
			'destination host' => "#^[0-9a-z\-_.:]+$#i",
			'destination subnet' => "#^[0-9a-z\-_.:]+$#i",
			'destination network' => "#^[0-9a-z\-_.:]+$#i",
			'protocol' => array(0 => array('ip', 'tcp', 'udp', 'icmp', 'esp', 'gre'), 1 => '#^[0-9]{1,5}((-[0-9]{1,5})|(:[0-9]{1,2}))?$#i'),	// ICMP type[:code]
			'description' => "#^\"?([a-z0-9\-_.,;+=()\[\]/ ]+)\"?$#i",
			'modify host' => array(0 => '#^[0-9a-z\-_.]+$#i',
				1 => '#^(([0-9]{1,3}\.){3}[0-9]{1,3})|([a-f0-9:]+)$#i',
				2 => '#^(([0-9]{1,3}\.){3}[0-9]{1,3})|([a-f0-9:]+)$#i'
			),		// IPv4/IPv6
			'modify subnet' => array(0 => '#^[0-9a-z\-_.]+$#i',
				1 => '#^(([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2})|([a-f0-9:]+/[0-9]{1,3})$#i',
				2 => '#^(([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2})|([a-f0-9:]+/[0-9]{1,3})$#i'
			),		// IPv4/IPv6
			'modify network' => array(0 => '#^[0-9a-z\-_.]+$#i',
				1 => '#^(([0-9]{1,3}\.){3}[0-9]{1,3}-[0-9]{1,3}\.){3}[0-9]{1,3})|([a-f0-9:]+-[a-f0-9:]+)$#i',
				2 => '#^(([0-9]{1,3}\.){3}[0-9]{1,3}-[0-9]{1,3}\.){3}[0-9]{1,3})|([a-f0-9:]+-[a-f0-9:]+)$#i'
			),		// IPv4/IPv6
			'modify rule' => '#^[0-9]+$#i',
			'remove host' => '#^[0-9a-z\-_.]+$#i',
			'remove subnet' => '#^[0-9a-z\-_.]+$#i',
			'remove network' => '#^[0-9a-z\-_.]+$#i',
			'remove rule' => '#^[0-9]+$#i',
			'export configuration' => array(0 => array('junos', 'junos_set'), 1 => array('force')),
			'export hosts' => array(0 => array('junos', 'junos_set'), 1 => array('force')),
			'export subnets' => array(0 => array('junos', 'junos_set'), 1 => array('force')),
			'export networks' => array(0 => array('junos', 'junos_set'), 1 => array('force')),
			'export rules' =>array(0 => array('junos', 'junos_set'), 1 => array('force')),
			'load' => "#^[0-9a-z\-_]+$#i",
			'save' => array(0 => "#^[0-9a-z\-_]+$#i", 1 => array('force')),
			'exit' => array(0 => array('force')),
			'quit' => array(0 => array('force')),
		);

		/**
		  * Arguments commencant pas par - ou -- donc hors flow de la commande
		  *
		  * find ... -type [type] -name [name]
		  */
		protected $_outlineArgCmds = array(
		);

		/**
		  * /!\ Ordre important
		  *
		  * L'ordre des commandes ci-dessous sera respecté
		  * afin que la configuration soit valide
		  */
		protected $_cliOptions = array(
			'short' => '',
			'long' => array(
				'load:',
				'site:',
				'create_host:',
				'create_subnet:',
				'create_network:',
				'create_rule:',
				'fullmesh::',
				'action:',
				'source_host:',
				'source_subnet:',
				'source_network:',
				'destination_host:',
				'destination_subnet:',
				'destination_network:',
				'protocol:',
				'description:',
				'show',
				'save::',
				'export_configuration:',
			)
		);

		protected $_cliToCmd = array(
			'load' => 'load',
			'show' => 'show',
			'site' => 'site',
			'create_host' => 'create host',
			'create_subnet' => 'create subnet',
			'create_network' => 'create network',
			'create_rule' => 'create rule',
			'fullmesh' => 'fullmesh',
			'action' => 'action',
			'source_host' => 'source host',
			'source_subnet' => 'source subnet',
			'source_network' => 'source network',
			'destination_host' => 'destination host',
			'destination_subnet' => 'destination subnet',
			'destination_network' => 'destination network',
			'protocol' => 'protocol',
			'description' => 'description',
			'save' => 'save',
			'export_configuration' => 'export configuration',
		);

		protected $_manCommands = array(
			'site' => "Indique sur quel(s) site(s) la/es règle(s) doit/doivent s'appliquer",
			'show' => "Affiche une section ou une entrée d'une section. Utilisation: show [site|host|subnet|network|rule] [name|ruleID]",
			'create host' => "Crée un object host custom. Utilisation: create host [name] [IPv4:address] [IPv6:address]",
			'create subnet' => "Crée un object subnet custom. Utilisation: create subnet [name] [IPv4:network/mask] [IPv6:network/mask]",
			'create network' => "Crée un object network custom. Utilisation: create network [name] [IPv4:ipFirst-ipLast] [IPv6:ipFirst-ipLast]",
			'create rule' => "Crée une règle de filtrage",
			'create rule monosite' => "Crée une règle sans flux de backup",
			'create rule failover' => "Crée une règle avec flux de backup",
			'fullmesh' => "Indique que cette règle doit être full meshée",
			'action' => "Configure la règle en autorisation ou en interdiction (permit|deny)",
			'source' => "Configure une ou plusieurs source(s)",
			'destination' => "Configure une ou plusieurs destination(s)",
			'protocol' => "Configure un ou plusieurs protocole(s)",
			'description' => "Ajoute une description à la règle",
			'check' => "Vérifie la règle en cours d'édition et retourne l'erreur si il y en a une",
			'reset' => "Réinitialise sources, destinations et protocoles pour la règle en cours d'édition",
			'reset source' => "Réinitialise les sources pour la règle en cours d'édition",
			'reset destination' => "Réinitialise les destinations pour la règle en cours d'édition",
			'reset protocol' => "Réinitialise les protocoles pour la règle en cours d'édition",
			'modify' => "Modifie une entrée d'une section",
			'remove' => "Supprime une entrée d'une section",
			'clear' => "Supprime entièrement une section",
			'export' => "Exporte la configuration dans un format défini. Utilisation: export [configuration|hosts|subnets|networks|rules] [format] [force]",
			'load' => "Charge une configuration. Utilisation: load [name]",
			'save' => "Sauvegarde la configuration. Utilisation: save [name] [force]",
			'firewall' => "Lance la GUI du FIREWALL",
			'ls' => "Affiche la liste des objets (hosts, subnets, networks, rules)",
			'll' => "Alias de ls",
			'find' => "Recherche avancée d'éléments. Utilisation: find . [type] [recherche]",
			'history' => "Affiche l'historique des commandes",
			'exit' => "Ferme le shell",
			'quit' => "Alias de exit",
		);


		public function __construct($configFilename, array $servers, $autoInitialisation = true)
		{
			parent::__construct($configFilename);

			$printInfoMessages = !$this->isOneShotCall();

			if(count($servers) > 0) {
				$IPAM = new IPAM($servers, $printInfoMessages);
				$this->_IPAM = $IPAM->getAllIpam();
				Ipam_Api_Abstract::setIpam($this->_IPAM);
			}

			$this->_Firewall_Sites = new Firewall_Sites($this->_CONFIG);
			$sites = $this->_Firewall_Sites->getSiteKeys();

			$this->_Service_Shell = new Service_Shell_Firewall($this, $this->_SHELL);

			$aSites = array_merge(array('all'), $sites);	// 'all' en premier

			$this->_SHELL->setInlineArg('site', array(0 => $aSites));
			$this->_SHELL->setInlineArg('show site', array(0 => $sites));
			$this->_SHELL->setInlineArg('remove site', array(0 => $aSites));
			$this->_SHELL->setInlineArg('firewall', array(0 => $sites));

			$shellAutoC_srcDst = Closure::fromCallable(array($this->_Service_Shell, 'shellAutoC_srcDst'));

			foreach(array('source', 'destination') as $attribute)
			{
				foreach(array('host', 'subnet', 'network') as $type) {
					$this->_SHELL->setInlineArg($attribute.' '.$type, $shellAutoC_srcDst);
				}
			}

			if($autoInitialisation) {
				$this->_init();
			}
		}

		protected function _launchShell()
		{
			$exit = false;

			while(!$exit)
			{
				list($cmd, $args) = $this->_SHELL->launch();

				$this->_preRoutingShellCmd($cmd, $args);
				$exit = $this->_routeShellCmd($cmd, $args);
				$this->_postRoutingShellCmd($cmd, $args);
			}
		}

		protected function _preLauchingShell($welcomeMessage = true)
		{
			parent::_preLauchingShell($welcomeMessage);

			$status = $this->_Service_Shell->autoload();

			if(!$status) {
				exit();
			}
		}

		protected function _cliOptToCmdArg($cli, $option)
		{
			$args = array();

			switch($cli)
			{
				// Without option
				case 'show':
				{
					break;
				}
				// Mono-Options (required)
				case 'load':
				case 'site':
				case 'create_rule':
				case 'action':
				case 'source_host':
				case 'source_subnet':
				case 'source_network':
				case 'destination_host':
				case 'destination_subnet':
				case 'destination_network':
				case 'protocol':
				case 'description':
				{
					$args = array($option);
					break;
				}
				// Mono-Options (optional)
				case 'fullmesh':
				case 'save':
				{
					if($option !== false) {
						$args = array($option);
					}

					break;
				}
				// Multi-Options (required)
				case 'create_host':
				case 'create_subnet':
				case 'create_network':
				case 'export_configuration':
				{
					$args = explode(self::CLI_OPTION_DELIMITER, $option);
					break;
				}
				default: {
					return false;
				}
			}

			if(array_key_exists($cli, $this->_cliToCmd)) {
				$cmd = $this->_cliToCmd[$cli];
			}
			else {
				$cmd = $cli;
			}

			$this->displayWaitingMsg();
			$this->_routeShellCmd($cmd, $args);
			return $this->_lastCmdStatus;
		}

		protected function _routeShellCmd($cmd, array $args)
		{
			$exit = false;

			switch($cmd)
			{
				case 'ls':
				case 'll':
				{
					$isPrinted = $this->_Service_Shell->printObjectInfos($args, true);

					if(!$isPrinted) {
						$this->deleteWaitingMsg(true);							// Fix PHP_EOL lié au double message d'attente successif lorsque la commande precedente n'a rien affichée
						$objects = $this->_Service_Shell->printObjectsList();
					}

					break;
				}
				case 'find':
				{
					$status = $this->_Service_Shell->printSearchObjects($args);
					break;
				}
				case 'show':
				{
					$status = $this->_Service_Shell->showConfig();
					break;
				}
				case 'show host':
				{
					$status = $this->_Service_Shell->showHost($args);
					break;
				}
				case 'show subnet':
				{
					$status = $this->_Service_Shell->showSubnet($args);
					break;
				}
				case 'show network':
				{
					$status = $this->_Service_Shell->showNetwork($args);
					break;
				}
				case 'show rule':
				{
					$status = $this->_Service_Shell->showRule($args);
					break;
				}
				case 'show hosts':
				{
					$status = $this->_Service_Shell->showHosts();
					break;
				}
				case 'show subnets':
				{
					$status = $this->_Service_Shell->showSubnets();
					break;
				}
				case 'show networks':
				{
					$status = $this->_Service_Shell->showNetworks();
					break;
				}
				case 'show rules':
				{
					$status = $this->_Service_Shell->showRules();
					break;
				}
				case 'create host':
				{
					$status = $this->_Service_Shell->createHost($args);
					break;
				}
				case 'create subnet':
				{
					$status = $this->_Service_Shell->createSubnet($args);
					break;
				}
				case 'create network':
				{
					$status = $this->_Service_Shell->createNetwork($args);
					break;
				}
				case 'create rule':
				{
					$status = $this->_Service_Shell->createRule($args);
					break;
				}
				case 'modify host':
				{
					$status = $this->_Service_Shell->modifyHost($args);
					break;
				}
				case 'modify subnet':
				{
					$status = $this->_Service_Shell->modifySubnet($args);
					break;
				}
				case 'modify network':
				{
					$status = $this->_Service_Shell->modifyNetwork($args);
					break;
				}
				case 'modify rule':
				{
					$status = $this->_Service_Shell->modifyRule($args);
					break;
				}
				case 'remove host':
				{
					$status = $this->_Service_Shell->removeHost($args);
					break;
				}
				case 'remove subnet':
				{
					$status = $this->_Service_Shell->removeSubnet($args);
					break;
				}
				case 'remove network':
				{
					$status = $this->_Service_Shell->removeNetwork($args);
					break;
				}
				case 'remove rule':
				{
					$status = $this->_Service_Shell->removeRule($args);
					break;
				}
				case 'clear':
				{
					$status = $this->_Service_Shell->clearAll();
					break;
				}
				case 'clear hosts':
				{
					$status = $this->_Service_Shell->clearHosts();
					break;
				}
				case 'clear subnets':
				{
					$status = $this->_Service_Shell->clearSubnets();
					break;
				}
				case 'clear networks':
				{
					$status = $this->_Service_Shell->clearNetworks();
					break;
				}
				case 'clear rules':
				{
					$status = $this->_Service_Shell->clearRules();
					break;
				}
				// ---------------------- RULE ----------------------
				case 'fullmesh': {
					$status = $this->_Service_Shell->rule_fullmesh($args);
					break;
				}
				case 'action': {
					$status = $this->_Service_Shell->rule_action($args);
					break;
				}
				case 'source host': {
					$status = $this->_Service_Shell->rule_source('host', $args);
					break;
				}
				case 'source subnet': {
					$status = $this->_Service_Shell->rule_source('subnet', $args);
					break;
				}
				case 'source network': {
					$status = $this->_Service_Shell->rule_source('network', $args);
					break;
				}
				case 'destination host': {
					$status = $this->_Service_Shell->rule_destination('host', $args);
					break;
				}
				case 'destination subnet': {
					$status = $this->_Service_Shell->rule_destination('subnet', $args);
					break;
				}
				case 'destination network': {
					$status = $this->_Service_Shell->rule_destination('network', $args);
					break;
				}
				case 'protocol': {
					$status = $this->_Service_Shell->rule_protocol($args);
					break;
				}
				case 'description': {
					$status = $this->_Service_Shell->rule_description($args);
					break;
				}
				case 'check': {
					$status = $this->_Service_Shell->rule_check();
					break;
				}
				case 'reset': {
					$status = $this->_Service_Shell->rule_reset();
					break;
				}
				case 'reset source': {
					$status = $this->_Service_Shell->rule_reset('source');
					break;
				}
				case 'reset destination': {
					$status = $this->_Service_Shell->rule_reset('destination');
					break;
				}
				case 'reset protocol': {
					$status = $this->_Service_Shell->rule_reset('protocol');
					break;
				}
				case 'exit':
				case 'quit':
				{
					$exitRule = $this->_Service_Shell->rule_exit();

					if(!$exitRule)
					{
						if(!$this->_Service_Shell->hasChanges() || (isset($args[0]) && $args[0] === 'force')) {
							$exit = parent::_routeShellCmd($cmd, $args);
						}
						else {
							$this->error("Vous n'avez pas sauvegardé la configuration, si vous souhaitez réellement quitter utilisez l'argument 'force'", 'orange');
						}
					}
					break;
				}
				// --------------------------------------------------
				// ---------------------- SITE ----------------------
				case 'site':
				{
					$status = $this->_Service_Shell->createSite($args);
					break;
				}
				case 'show site':
				{
					$status = $this->_Service_Shell->showSite($args);
					break;
				}
				case 'show sites':
				{
					$status = $this->_Service_Shell->showSites();
					break;
				}
				case 'remove site':
				{
					$status = $this->_Service_Shell->removeSite($args);
					break;
				}
				case 'clear sites':
				{
					$status = $this->_Service_Shell->clearSites();
					break;
				}
				// --------------------------------------------------
				// --------------------- CONFIG ---------------------
				case 'export configuration':
				{
					$status = $this->_Service_Shell->export(null, $args);
					break;
				}
				case 'export hosts':
				{
					$status = $this->_Service_Shell->export('host', $args);
					break;
				}
				case 'export subnets':
				{
					$status = $this->_Service_Shell->export('subnet', $args);
					break;
				}
				case 'export networks':
				{
					$status = $this->_Service_Shell->export('network', $args);
					break;
				}
				case 'export rules':
				{
					$status = $this->_Service_Shell->export('rule', $args);
					break;
				}
				case 'load':
				{
					$status = $this->_Service_Shell->load($args);
					break;
				}
				case 'save':
				{
					$status = $this->_Service_Shell->save($args);
					break;
				}
				// --------------------------------------------------
				case 'firewall':
				{
					if(isset($args[0]))
					{
						if(isset($this->_Firewall_Sites->{$args[0]}))
						{
							$FIREWALL_Site = $this->_Firewall_Sites->{$args[0]};
							$guiProtocol = $FIREWALL_Site->getGuiProtocol();
							$guiAddress = $FIREWALL_Site->getGuiAddress();

							switch($guiProtocol)
							{
								case 'http':
								case 'https':
									$address = $guiProtocol.'://'.$guiAddress;
									$cmd = $this->_CONFIG->DEFAULT->sys->browserCmd;
									break;
								case 'ssh':
									$address = $guiAddress;
									$cmd = $this->_CONFIG->DEFAULT->sys->secureShellCmd;
									break;
								default:
									throw new Exception("Remote GUI protocol '".$guiProtocol."' is not allowed", E_USER_ERROR);
							}

							$this->deleteWaitingMsg();
							$handle = popen($cmd.' "'.$address.'" > /dev/null 2>&1', 'r');
							pclose($handle);
						}
					}

					break;
				}
				default: {
					$exit = parent::_routeShellCmd($cmd, $args);
				}
			}

			if(isset($status))
			{
				$this->_lastCmdStatus = $status;

				if(!$status && !$this->_isOneShotCall)
				{
					if(array_key_exists($cmd, $this->_manCommands)) {
						$this->error($this->_manCommands[$cmd], 'red');
					}
					else {
						$this->error("Une erreur s'est produit lors de l'exécution de cette commande", 'red');
					}
				}
			}

			return $exit;
		}
	}