<?php
	namespace App\Firewall;

	use Closure;

	use Core as C;

	use Cli as Cli;

	use Addon\Ipam;

	use App\Firewall\Core;

	class Shell_Firewall extends Cli\Shell\Shell
	{
		const SHELL_HISTORY_FILENAME = '.firewall.history';

		const ARG_TYPES = array(
			'host' => Core\Api_Host::OBJECT_TYPE,
			'hosts' => Core\Api_Host::OBJECT_TYPE,
			'subnet' => Core\Api_Subnet::OBJECT_TYPE,
			'subnets' => Core\Api_Subnet::OBJECT_TYPE,
			'network' => Core\Api_Network::OBJECT_TYPE,
			'networks' => Core\Api_Network::OBJECT_TYPE,
			'rule' => Core\Api_Rule::OBJECT_TYPE,
			'rules' => Core\Api_Rule::OBJECT_TYPE,
			'flow' => Core\Api_Flow::OBJECT_TYPE,
			'flows' => Core\Api_Flow::OBJECT_TYPE,
		);

		const REGEX_ALL_ALL = "#^\"?[0-9a-z\-_.:\#/ ]+\"?$#i";
		const REGEX_ALL_ALL_WC = "#^\"?[0-9a-z\-_.:\#/ *]+\"?$#i";
		const REGEX_IPAM_NAME = "#^\"?[0-9a-z\-_.:\#/ ]+\"?$#i";
		const REGEX_IPAM_NAME_WC = "#^\"?[0-9a-z\-_.:\#/ *]+\"?$#i";
		const REGEX_ALL_NAME = "#^\"?[0-9a-z\-_.:\# ]+\"?$#i";
		const REGEX_ALL_NAME_WC = "#^\"?[0-9a-z\-_.:\# *]+\"?$#i";
		const REGEX_HOST_NAME = "#^\"?[0-9a-z\-_.:\# ]+\"?$#i";
		const REGEX_HOST_NAME_WC = "#^\"?[0-9a-z\-_.:\# *]+\"?$#i";
		const REGEX_SUBNET_NAME = "#^\"?[0-9a-z\-_.:\# ]+\"?$#i";
		const REGEX_SUBNET_NAME_WC = "#^\"?[0-9a-z\-_.:\# *]+\"?$#i";
		const REGEX_NETWORK_NAME = "#^\"?[0-9a-z\-_.:\# ]+\"?$#i";
		const REGEX_NETWORK_NAME_WC = "#^\"?[0-9a-z\-_.:\# *]+\"?$#i";
		const REGEX_RULE_NAME = "#^\"?[0-9a-z\-_]+\"?$#i";
		const REGEX_RULE_DESC = "#^\"?([[:print:]]*)\"?$#i";								// * and not + to allow empty description
		const REGEX_RULE_DESC_WC = "#^\"?([[:print:]]+)\"?$#i";
		const REGEX_RULE_TAG = "#^[[:print:]]+$#i";
		const REGEX_RULE_TAG_WC = "#^[[:print:]]+$#i";
		const REGEX_RULE_FIELD_PRINT = "#^[[:print:]]+$#i";
		const REGEX_CONFIG_FILE_PRINT = "#^\"?[[:print:]]+\"?$#i";

		const PROTOCOLS = array('ip', 'tcp', 'udp', 'icmp', 'icmp6', 'esp', 'gre');

		const REGEX_ADDRESS = "#^\"?[0-9a-f.:\/\-]+\"?$#i";
		const REGEX_PROTOCOL = "#^\"?[0-9]{1,5}((-[0-9]{1,5})|(:[0-9]{1,3}))?\"?$#i";		// ICMP type[:code]

		protected $_commands = array(
			'help', 'history',
			'ls', 'll', 'exit', 'quit',
			'find', 'search',
			'show' => array(
				'site', 'host', 'subnet', 'network', 'rule', 
				'sites', 'hosts', 'subnets', 'networks', 'rules', 
			),
			'locate' => array('host', 'subnet', 'network', 'rule', 'flow'),
			'filter' => array(
				'duplicates',
				'rules' => array('duplicates'),
			),
			'create' => array('host', 'subnet', 'network', 'rule'),
			'clone' => array('rule'),
			'site',
			'category', 'fullmesh',
			'action', 'status',
			'source' => array('host', 'subnet', 'network'),
			'destination' => array('host', 'subnet', 'network'),
			'protocol',
			'description',
			'tag', 'tags',
			'check',
			'reset' => array(
				'source' => array('host', 'subnet', 'network'),
				'destination' => array('host', 'subnet', 'network'),
				'protocol',
				'sources', 'destinations', 'protocols',
				'tag', 'tags'
			),
			'modify' => array('host', 'subnet', 'network', 'rule'),
			'refresh' => array(
				'host', 'subnet', 'network',
				'hosts', 'subnets', 'networks',
			),
			'replace',
			'rename' => array('host', 'subnet', 'network', 'rule'),
			'remove' => array('site', 'host', 'subnet', 'network', 'rule'),
			'clear' => array('sites', 'hosts', 'subnets', 'networks', 'rules'),
			//'export' => array('configuration', 'hosts', 'subnets', 'networks', 'rules'),	// @todo a coder
			'import' => array('configuration'),
			'export' => array('configuration', 'rules'),
			'copy' => array('configuration'),
			'ipam' => array('search', 'import'),
			'load', 'run', 'save',
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
			'ls' => self::REGEX_ALL_NAME,
			'll' => self::REGEX_ALL_NAME,
			'find' => array(
				0 => "#^\.$#i",
				1 => array('all', 'host', 'subnet', 'network', 'rule'),
				2 => self::REGEX_ALL_ALL_WC
			),
			'search' => array(
				0 => array('all', 'host', 'subnet', 'network', 'rule'),
				1 => self::REGEX_ALL_ALL_WC
			),
			'show host' => self::REGEX_HOST_NAME_WC,
			'show subnet' => self::REGEX_SUBNET_NAME_WC,
			'show network' => self::REGEX_NETWORK_NAME_WC,
			'show rule' => self::REGEX_RULE_NAME,
			'show hosts' => self::REGEX_HOST_NAME_WC,
			'show subnets' => self::REGEX_SUBNET_NAME_WC,
			'show networks' => self::REGEX_NETWORK_NAME_WC,
			'show rules' => self::REGEX_RULE_NAME,
			'locate host' => array(0 => self::REGEX_HOST_NAME, 1 => array('exact')),
			'locate subnet' => array(0 => self::REGEX_SUBNET_NAME_WC, 1 => array('exact')),
			'locate network' => array(0 => self::REGEX_NETWORK_NAME_WC, 1 => array('exact')),
			'locate rule' => array(0 => self::REGEX_RULE_FIELD_PRINT, 1 => array('exact')),
			'locate flow' => array(
				0 => array('source'),
				1 => self::REGEX_ADDRESS,
				2 => array('destination'),
				3 => self::REGEX_ADDRESS,
				4 => array('protocol'),
				5 => self::PROTOCOLS,
				6 => self::REGEX_PROTOCOL
			),
			'filter duplicates' => array(
				0 => array('hosts', 'subnets', 'networks', 'rules', 'flows'),
			),
			'filter rules duplicates' => array(
				0 => array('addresses', 'protocols', 'tags', 'all'),
			),
			'create host' => array(
				0 => self::REGEX_HOST_NAME,
				1 => '#^\"?(([0-9]{1,3}\.){3}[0-9]{1,3})|([a-f0-9:]+)\"?$#i',
				2 => '#^\"?(([0-9]{1,3}\.){3}[0-9]{1,3})|([a-f0-9:]+)\"?$#i'
			),		// IPv4/IPv6
			'create subnet' => array(
				0 => self::REGEX_SUBNET_NAME,
				1 => '#^\"?(([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2})|([a-f0-9:]+/[0-9]{1,3})\"?$#i',
				2 => '#^\"?(([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2})|([a-f0-9:]+/[0-9]{1,3})\"?$#i'
			),		// IPv4/IPv6
			'create network' => array(
				0 => self::REGEX_NETWORK_NAME,
				1 => '#^\"?(([0-9]{1,3}\.){3}[0-9]{1,3}-[0-9]{1,3}\.){3}[0-9]{1,3})|([a-f0-9:]+-[a-f0-9:]+)\"?$#i',
				2 => '#^\"?(([0-9]{1,3}\.){3}[0-9]{1,3}-[0-9]{1,3}\.){3}[0-9]{1,3})|([a-f0-9:]+-[a-f0-9:]+)\"?$#i'
			),		// IPv4/IPv6
			'create rule' => array(0 => array('monosite', 'failover'), 1 => self::REGEX_RULE_NAME),
			'clone rule' => array(0 => self::REGEX_RULE_NAME, 1 => self::REGEX_RULE_NAME),
			'category' => array(0 => array('monosite', 'failover')),
			'fullmesh' => array(0 => array('enable', 'disable')),
			'action' => array(0 => array('permit', 'deny')),
			'status' => array(0 => array('enable', 'disable')),
			'source host' => self::REGEX_HOST_NAME,
			'source subnet' => self::REGEX_SUBNET_NAME,
			'source network' => self::REGEX_NETWORK_NAME,
			'destination host' => self::REGEX_HOST_NAME,
			'destination subnet' => self::REGEX_SUBNET_NAME,
			'destination network' => self::REGEX_NETWORK_NAME,
			'protocol' => array(0 => self::PROTOCOLS, 1 => self::REGEX_PROTOCOL),
			'description' => self::REGEX_RULE_DESC,
			'tag' => self::REGEX_RULE_TAG,
			'tags' => array(),		//see __construct
			'reset source host' => self::REGEX_HOST_NAME,
			'reset source subnet' => self::REGEX_SUBNET_NAME,
			'reset source network' => self::REGEX_NETWORK_NAME,
			'reset destination host' => self::REGEX_HOST_NAME,
			'reset destination subnet' => self::REGEX_SUBNET_NAME,
			'reset destination network' => self::REGEX_NETWORK_NAME,
			'reset protocol' => array(0 => self::PROTOCOLS, 1 => self::REGEX_PROTOCOL),
			'reset tag' => self::REGEX_RULE_TAG,
			'modify host' => array(
				0 => self::REGEX_HOST_NAME,
				1 => '#^(([0-9]{1,3}\.){3}[0-9]{1,3})|([a-f0-9:]+)$#i',
				2 => '#^(([0-9]{1,3}\.){3}[0-9]{1,3})|([a-f0-9:]+)$#i'
			),		// IPv4/IPv6
			'modify subnet' => array(
				0 => self::REGEX_SUBNET_NAME,
				1 => '#^(([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2})|([a-f0-9:]+/[0-9]{1,3})$#i',
				2 => '#^(([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2})|([a-f0-9:]+/[0-9]{1,3})$#i'
			),		// IPv4/IPv6
			'modify network' => array(
				0 => self::REGEX_NETWORK_NAME,
				1 => '#^(([0-9]{1,3}\.){3}[0-9]{1,3}-[0-9]{1,3}\.){3}[0-9]{1,3})|([a-f0-9:]+-[a-f0-9:]+)$#i',
				2 => '#^(([0-9]{1,3}\.){3}[0-9]{1,3}-[0-9]{1,3}\.){3}[0-9]{1,3})|([a-f0-9:]+-[a-f0-9:]+)$#i'
			),		// IPv4/IPv6
			'modify rule' => self::REGEX_RULE_NAME,
			'refresh host' => array(0 => self::REGEX_HOST_NAME),
			'refresh subnet' => array(0 => self::REGEX_SUBNET_NAME),
			'refresh network' => array(0 => self::REGEX_NETWORK_NAME),
			'replace' => array(
				0 => array('host', 'subnet', 'network'),
				1 => self::REGEX_ALL_NAME,
				2 => array('host', 'subnet', 'network'),
				3 => self::REGEX_ALL_NAME,
			),
			'rename host' => array(0 => self::REGEX_HOST_NAME, 1 => self::REGEX_HOST_NAME),
			'rename subnet' => array(0 => self::REGEX_SUBNET_NAME, 1 => self::REGEX_SUBNET_NAME),
			'rename network' => array(0 => self::REGEX_NETWORK_NAME, 1 => self::REGEX_NETWORK_NAME),
			'rename rule' => array(0 => self::REGEX_RULE_NAME, 1 => self::REGEX_RULE_NAME),
			'remove host' => self::REGEX_HOST_NAME,
			'remove subnet' => self::REGEX_SUBNET_NAME,
			'remove network' => self::REGEX_NETWORK_NAME,
			'remove rule' => self::REGEX_RULE_NAME,
			'import configuration' => array(0 => array('csv', 'json'), 1 => self::REGEX_CONFIG_FILE_PRINT, 2 => "#^[\S]+$#i", 3 => array('force')),
			'export configuration' => array(0 => array('cisco_asa', 'cisco_asa-dap', 'juniper_junos', 'juniper_junos-set'), 1 => array('force')),			// /!\ voir __construct
			'export rules' => array(0 => array('web_html'), 1 => array('force')),
			'copy configuration' => array(0 => array(), 1 => array('scp')),																					// /!\ voir __construct
			'ipam search' => array(
				0 => array('all', 'host', 'subnet'),
				1 => self::REGEX_IPAM_NAME_WC
			),
			'ipam import' => array(
				0 => array('host', 'subnet'),
				1 => self::REGEX_IPAM_NAME_WC
			),
			'load' => array(0 => self::REGEX_CONFIG_FILE_PRINT, 1 => "#^[\S]+$#i", 2 => array('force')),
			'run' => array(0 => self::REGEX_CONFIG_FILE_PRINT, 2 => array('force')),
			'save' => array(0 => self::REGEX_CONFIG_FILE_PRINT, 1 => array('force')),
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
				'category::',
				'fullmesh::',
				'action:',
				'status:',
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
				'import_configuration:',
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
			'category' => 'category',
			'fullmesh' => 'fullmesh',
			'action' => 'action',
			'status' => 'status',
			'source_host' => 'source host',
			'source_subnet' => 'source subnet',
			'source_network' => 'source network',
			'destination_host' => 'destination host',
			'destination_subnet' => 'destination subnet',
			'destination_network' => 'destination network',
			'protocol' => 'protocol',
			'description' => 'description',
			'save' => 'save',
			'import_configuration' => 'import configuration',
			'export_configuration' => 'export configuration',
		);

		protected $_manCommands = array(
			'site' => "Indique sur quel(s) site(s) la/es règle(s) doit/doivent s'appliquer",
			'search' => "Recherche avancée d'éléments custom. Utilisation: search [type] [recherche]",
			'show' => "Affiche une section ou une entrée d'une section. Utilisation: show [site|host|subnet|network|rule] [name|ruleID]",
			'locate' => "Recherche d'éléments utilisés dans les règles. Utilisation: locate [type] [recherche] [exact]",
			'locate flow' => "Recherche d'un flow utilisé dans les règles. Utilisation: locate flow source [address] destination [address] protocol [protoName] [protoOptions]",
			'filter' => "Applique un filtre spécial puis affiche le résultat. Utilisation: filter [name] [options]",
			'filter rules' => "Applique un filtre spécial sur les règles puis affiche le résultat. Utilisation: filter rules [name] [options]",
			'create host' => "Crée un objet host custom. Utilisation: create host [name] [IPv4:address] [IPv6:address]",
			'create subnet' => "Crée un objet subnet custom. Utilisation: create subnet [name] [IPv4:network/mask] [IPv6:network/mask]",
			'create network' => "Crée un objet network custom. Utilisation: create network [name] [IPv4:ipFirst-ipLast] [IPv6:ipFirst-ipLast]",
			'create rule' => "Crée une règle de filtrage. Utilisation: create rule [monosite|failover] [name]",
			'create rule monosite' => "Crée une règle sans flux de backup. Utilisation: create rule monosite [name]",
			'create rule failover' => "Crée une règle avec flux de backup. Utilisation: create rule failover [name]",
			'clone' => "Clone un objet. Utilisation: clone [type]",
			'clone rule' => "Clone une règle. Utilisation: clone rule [srcName] [dstName]",
			'category' => "Indique la catégorie de la règle",
			'category monosite' => "Règle sans flux de backup",
			'category failover' => "Règle avec flux de backup",
			'fullmesh' => "Indique que cette règle doit être full meshée",
			'action' => "Configure la règle en autorisation ou en interdiction (permit|deny)",
			'status' => "Configure la règle pour être active ou désactivée (enable|disable)",
			'source' => "Configure une ou plusieurs source(s)",
			'destination' => "Configure une ou plusieurs destination(s)",
			'protocol' => "Configure un ou plusieurs protocole(s)",
			'description' => "Ajoute une description à la règle",
			'tag' => "Ajoute un tag à la règle. Utilisation: tag [tag]",
			'tags' => "Ajoute plusieurs tags à la règle. Utilisation: tags [tag1] [tag2] [tag3] ...",
			'check' => "Vérifie l'ensemble des règles ou la règle en cours d'édition et retourne l'erreur si il y en a une",
			'reset' => "Réinitialise sources, destinations et protocoles pour la règle en cours d'édition. Utilisation: reset [source|sources|destination|destinations|protocol|protocols]",
			'reset source' => "Réinitialise une source pour la règle en cours d'édition",
			'reset destination' => "Réinitialise une destination pour la règle en cours d'édition",
			'reset protocol' => "Réinitialise un protocole pour la règle en cours d'édition",
			'reset tag' => "Réinitialise un tag pour la règle en cours d'édition",
			'reset sources' => "Réinitialise les sources pour la règle en cours d'édition",
			'reset destinations' => "Réinitialise les destinations pour la règle en cours d'édition",
			'reset protocols' => "Réinitialise les protocoles pour la règle en cours d'édition",
			'reset tags' => "Réinitialise les tags pour la règle en cours d'édition",
			'modify' => "Modifie une entrée d'une section",
			'modify host' => "Modifie un objet host custom. Utilisation: modify host [name] [IPv4:address] [IPv6:address]",
			'modify subnet' => "Modifie un objet subnet custom. Utilisation: modify subnet [name] [IPv4:network/mask] [IPv6:network/mask]",
			'modify network' => "Modifie un objet network custom. Utilisation: modify network [name] [IPv4:ipFirst-ipLast] [IPv6:ipFirst-ipLast]",
			'modify rule' => "Modifie une règle de filtrage. Utilisation: modify rule [id]",
			'refresh' => "Actualise un objet à partir de l'IPAM",
			'refresh host' => "Actualise un objet host custom. Utilisation: refresh host [name]",
			'refresh subnet' => "Actualise un objet subnet custom. Utilisation: refresh subnet [name]",
			'refresh network' => "Actualise un objet network custom. Utilisation: refresh network [name]",
			'replace' => "Remplace dans les règles un objet custom par un autre",
			'replace host' => "Remplace dans les règles un objet host custom par un autre. Utilisation: replace host [currentName] [newType] [newName]",
			'replace subnet' => "Remplace dans les règles un objet subnet custom par un autre. Utilisation: replace subnet [currentName] [newType] [newName]",
			'replace network' => "Remplace dans les règles un objet network custom par un autre. Utilisation: replace network [currentName] [newType] [newName]",
			'rename' => "Renomme un objet ou une règle",
			'rename host' => "Renomme un objet host custom. Utilisation: rename host [currentName] [newName]",
			'rename subnet' => "Renomme un objet subnet custom. Utilisation: rename subnet [currentName] [newName]",
			'rename network' => "Renomme un objet network custom. Utilisation: rename network [currentName] [newName]",
			'rename rule' => "Renomme une règle de filtrage. Utilisation: rename rule [currentId] [newId]",
			'remove' => "Supprime une entrée d'une section",
			'remove host' => "Supprime un objet host custom. Utilisation: remove host [name]",
			'remove subnet' => "Supprime un objet subnet custom. Utilisation: remove subnet [name]",
			'remove network' => "Supprime un objet network custom. Utilisation: remove network [name]",
			'remove rule' => "Supprime une règle de filtrage. Utilisation: remove rule [id]",
			'clear' => "Supprime entièrement une section",
			'import' => "Importe la configuration depuis un format défini. Utilisation: import [section]",
			'import configuration' => "Importe la configuration depuis un format défini. Utilisation: import configuration [format] [filename] [prefix] [force]",
			'export' => "Exporte la configuration vers un format défini. Utilisation: export [section]",
			'export configuration' => "Exporte la configuration vers un format défini. Utilisation: export configuration [format] [force]",
			'export rules' => "Exporte les règles vers un format défini. Utilisation: export rules [format] [force]",
			'copy' => "Copie la configuration vers un emplacement défini. Utilisation: copy [section]",
			'copy configuration' => "Copie la configuration vers un emplacement défini. Utilisation: copy configuration [format] [method] [site]",
			'ipam' => "Interraction avec l'IPAM (recherche, ...)",
			'ipam search' => "Recherche avancée d'éléments dans l'IPAM. Utilisation: ipam search [type] [recherche]",
			'ipam import' => "Importe un élément de l'IPAM dans l'inventaire local. Utilisation: ipam import [type] [recherche]",
			'load' => "Charge une configuration. Utilisation: load [filename][.json|.csv] [prefix] [force]",
			'run' => "Exécute les commandes. Utilisation: run [filename] [force]",
			'save' => "Sauvegarde la configuration. Utilisation: save [name] [force]",
			'firewall' => "Lance la GUI du FIREWALL",
			'ls' => "Affiche la liste des objets (hosts, subnets, networks, rules)",
			'll' => "Alias de ls",
			'find' => "Recherche avancée d'éléments. Utilisation: find . [type] [recherche]",
			'history' => "Affiche l'historique des commandes",
			'exit' => "Ferme le shell",
			'quit' => "Alias de exit",
		);

		/**
		  * @var App\Firewall\Core\Sites
		  */
		protected $_sites = null;


		public function __construct($configFilename, array $servers, $autoInitialisation = true)
		{
			parent::__construct($configFilename);

			if(!$this->isOneShotCall()) {
				$printInfoMessages = true;
				ob_end_flush();
			}
			else {
				$printInfoMessages = false;
			}

			if(count($servers) > 0) {
				$this->_initAddons($servers, $printInfoMessages);
			}

			$this->_sites = new Core\Sites($this->_CONFIG);
			$sites = $this->_sites->getSiteKeys();

			$this->_PROGRAM = new Shell_Program_Firewall($this, $this->_TERMINAL);

			$aSites = array_merge(array('all'), $sites);	// 'all' en premier

			$cpConfInlineArgs = $this->_inlineArgCmds['copy configuration'];
			$cpConfInlineArgs[0] = $this->_inlineArgCmds['export configuration'][0];
			$cpConfInlineArgs[2] = $sites;

			$this->_TERMINAL->setInlineArg('site', array(0 => $aSites));
			$this->_TERMINAL->setInlineArg('show site', array(0 => $sites));
			$this->_TERMINAL->setInlineArg('remove site', array(0 => $aSites));
			$this->_TERMINAL->setInlineArg('copy configuration', $cpConfInlineArgs);
			$this->_TERMINAL->setInlineArg('firewall', array(0 => $sites));

			$shellAutoC_srcDst = Closure::fromCallable(array($this->_PROGRAM, 'shellAutoC_srcDst'));

			foreach(array('source', 'destination') as $attribute)
			{
				foreach(array('host', 'subnet', 'network') as $type) {
					$this->_inlineArgCmds[$attribute.' '.$type] = $shellAutoC_srcDst;
					$this->_TERMINAL->setInlineArg($attribute.' '.$type, $shellAutoC_srcDst);
				}
			}

			$this->_inlineArgCmds['tags'] = array_fill(0, 9, self::REGEX_RULE_TAG);
			$this->_TERMINAL->setInlineArg('tags', $this->_inlineArgCmds['tags']);

			$this->_inlineArgCmds['load'][0] = Closure::fromCallable(array($this->_PROGRAM, 'shellAutoC_load'));
			$this->_TERMINAL->setInlineArg('load', $this->_inlineArgCmds['load']);

			$this->_inlineArgCmds['run'][0] = Closure::fromCallable(array($this->_PROGRAM, 'shellAutoC_filesystem'));
			$this->_TERMINAL->setInlineArg('run', $this->_inlineArgCmds['run']);

			$this->_inlineArgCmds['import configuration'][1] = Closure::fromCallable(array($this->_PROGRAM, 'shellAutoC_filesystem'));
			$this->_TERMINAL->setInlineArg('import configuration', $this->_inlineArgCmds['import configuration']);

			if($autoInitialisation) {
				$this->_init();
			}
		}

		protected function _initAddons(array $servers, $printInfoMessages)
		{
			$Addon_Orchestrator = Ipam\Orchestrator::getInstance($this->_CONFIG->IPAM);
			$Addon_Orchestrator->debug($this->_addonDebug);

			foreach($servers as $server)
			{
				$Addon_Service = $Addon_Orchestrator->newService($server);

				if($printInfoMessages) {
					$adapterMethod = $Addon_Service->getMethod();
					C\Tools::e(PHP_EOL."Connection ".$adapterMethod." à l'IPAM @ ".$server." veuillez patienter ... ", 'blue');
				}

				try {
					$isReady = $Addon_Service->initialization();
				}
				catch(\Exception $e) {
					if($printInfoMessages) { C\Tools::e("[KO]", 'red'); }
					$this->error("Impossible de démarrer le service IPAM:".PHP_EOL.$e->getMessage(), 'red');
					exit;
				}

				if(!$isReady) {
					if($printInfoMessages) { C\Tools::e("[KO]", 'red'); }
					$this->error("Le service IPAM n'a pas pu être correctement initialisé", 'red');
					exit;
				}

				if($printInfoMessages) {
					C\Tools::e("[OK]", 'green');
				}
			}
		}

		protected function _preLauchingShell($welcomeMessage = true)
		{
			parent::_preLauchingShell($welcomeMessage);

			$status = $this->_PROGRAM->autoload();

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
				case 'category':
				case 'action':
				case 'status':
				case 'source_host':
				case 'source_subnet':
				case 'source_network':
				case 'destination_host':
				case 'destination_subnet':
				case 'destination_network':
				case 'protocol':
				case 'description':
				case 'tag':
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
				case 'import_configuration':
				case 'export_configuration':
				case 'tags':
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

			return (
				$this->_RESULTS->isTrue() ||
				$this->_RESULTS->isNull()
			);
		}

		protected function _routeShellCmd($cmd, array $args)
		{
			$exit = false;

			switch($cmd)
			{
				case 'ls':
				case 'll':
				{
					$isPrinted = $this->_PROGRAM->printObjectInfos($args, true);

					if(!$isPrinted) {
						$this->deleteWaitingMsg(true);							// Fix PHP_EOL lié au double message d'attente successif lorsque la commande precedente n'a rien affichée
						$objects = $this->_PROGRAM->printObjectsList();
						$this->_RESULTS->append($objects);
					}

					break;
				}
				case 'find':
				{
					$status = $this->_PROGRAM->printSearchObjects($args);
					break;
				}
				// ---------------------- SITE ----------------------
				case 'site':
				{
					$status = $this->_PROGRAM->createSite($args);
					break;
				}
				case 'show site':
				{
					$status = $this->_PROGRAM->showSite($args);
					break;
				}
				case 'show sites':
				{
					$status = $this->_PROGRAM->showSites();
					break;
				}
				case 'remove site':
				{
					$status = $this->_PROGRAM->removeSite($args);
					break;
				}
				case 'clear sites':
				{
					$status = $this->_PROGRAM->clearSites();
					break;
				}
				// --------------------------------------------------

				// --------------------- OBJECT ---------------------
					// OBJECT > SHOW
					case 'show': {
						$status = $this->_PROGRAM->showConfig();
						break;
					}
					case 'show host': {
						$status = $this->_PROGRAM->showHost($args);
						break;
					}
					case 'show subnet': {
						$status = $this->_PROGRAM->showSubnet($args);
						break;
					}
					case 'show network': {
						$status = $this->_PROGRAM->showNetwork($args);
						break;
					}
					case 'show rule': {
						$status = $this->_PROGRAM->showRule($args);
						break;
					}
					case 'show hosts': {
						$status = $this->_PROGRAM->showHosts($args);
						break;
					}
					case 'show subnets': {
						$status = $this->_PROGRAM->showSubnets($args);
						break;
					}
					case 'show networks': {
						$status = $this->_PROGRAM->showNetworks($args);
						break;
					}
					case 'show rules': {
						$status = $this->_PROGRAM->showRules($args);
						break;
					}
					// --------------------------------------------------

					// OBJECT > LOCATE
					case 'locate host': {
						$status = $this->_PROGRAM->locateHost($args);
						break;
					}
					case 'locate subnet': {
						$status = $this->_PROGRAM->locateSubnet($args);
						break;
					}
					case 'locate network': {
						$status = $this->_PROGRAM->locateNetwork($args);
						break;
					}
					case 'locate rule': {
						$status = $this->_PROGRAM->locateRule($args);
						break;
					}
					case 'locate flow': {
						$status = $this->_PROGRAM->locateFlow($args);
						break;
					}
					// --------------------------------------------------

					// OBJECT > FILTER
					case 'filter duplicates':
					{
						if(count($args) === 1 && array_key_exists($args[0], self::ARG_TYPES)) {
							$status = $this->_PROGRAM->filter('duplicates', self::ARG_TYPES[$args[0]]);
						}
						else {
							$status = false;
						}
						break;
					}
					case 'filter rules duplicates': {
						$status = $this->_PROGRAM->filterRules('duplicates', $args);
						break;
					}
					// --------------------------------------------------

					// OBJECT > CREATE
					case 'create host': {
						$status = $this->_PROGRAM->createHost($args);
						break;
					}
					case 'create subnet': {
						$status = $this->_PROGRAM->createSubnet($args);
						break;
					}
					case 'create network': {
						$status = $this->_PROGRAM->createNetwork($args);
						break;
					}
					case 'create rule': {
						$status = $this->_PROGRAM->createRule($args);
						break;
					}
					case 'clone rule': {
						$status = $this->_PROGRAM->cloneRule($args);
						break;
					}
					// --------------------------------------------------

					// OBJECT > MODIFY
					case 'modify host': {
						$status = $this->_PROGRAM->modifyHost($args);
						break;
					}
					case 'modify subnet': {
						$status = $this->_PROGRAM->modifySubnet($args);
						break;
					}
					case 'modify network': {
						$status = $this->_PROGRAM->modifyNetwork($args);
						break;
					}
					case 'modify rule': {
						$status = $this->_PROGRAM->modifyRule($args);
						break;
					}
					// --------------------------------------------------

					// OBJECT > REFRESH
					case 'refresh host': {
						$status = $this->_PROGRAM->refreshHost($args);
						break;
					}
					case 'refresh subnet': {
						$status = $this->_PROGRAM->refreshSubnet($args);
						break;
					}
					case 'refresh network': {
						$status = $this->_PROGRAM->refreshNetwork($args);
						break;
					}
					case 'refresh hosts': {
						$status = $this->_PROGRAM->refreshHosts();
						break;
					}
					case 'refresh subnets': {
						$status = $this->_PROGRAM->refreshSubnets();
						break;
					}
					case 'refresh networks': {
						$status = $this->_PROGRAM->refreshNetworks();
						break;
					}
					// --------------------------------------------------

					// OBJECT > REPLACE
					case 'replace': {
						$status = $this->_PROGRAM->replace($args);
						break;
					}
					// --------------------------------------------------

					// OBJECT > RENAME
					case 'rename host': {
						$status = $this->_PROGRAM->renameHost($args);
						break;
					}
					case 'rename subnet': {
						$status = $this->_PROGRAM->renameSubnet($args);
						break;
					}
					case 'rename network': {
						$status = $this->_PROGRAM->renameNetwork($args);
						break;
					}
					case 'rename rule': {
						$status = $this->_PROGRAM->renameRule($args);
						break;
					}
					// --------------------------------------------------

					// OBJECT > REMOVE
					case 'remove host': {
						$status = $this->_PROGRAM->removeHost($args);
						break;
					}
					case 'remove subnet': {
						$status = $this->_PROGRAM->removeSubnet($args);
						break;
					}
					case 'remove network': {
						$status = $this->_PROGRAM->removeNetwork($args);
						break;
					}
					case 'remove rule': {
						$status = $this->_PROGRAM->removeRule($args);
						break;
					}
					// --------------------------------------------------

					// OBJECT > CLEAR
					case 'clear': {
						$status = $this->_PROGRAM->clearAll();
						break;
					}
					case 'clear hosts': {
						$status = $this->_PROGRAM->clearHosts();
						break;
					}
					case 'clear subnets': {
						$status = $this->_PROGRAM->clearSubnets();
						break;
					}
					case 'clear networks': {
						$status = $this->_PROGRAM->clearNetworks();
						break;
					}
					case 'clear rules': {
						$status = $this->_PROGRAM->clearRules();
						break;
					}
					// --------------------------------------------------
				// --------------------------------------------------

				// ---------------------- LOCAL ---------------------
				case 'search':
				{
					if(count($args) === 2) {
						$status = $this->_PROGRAM->search($args[0], $args[1]);
					}
					else {
						$status = false;
					}
					break;
				}
				// --------------------------------------------------

				// ---------------------- IPAM ----------------------
				case 'ipam search':
				{
					if(count($args) === 2) {
						$status = $this->_PROGRAM->ipamSearch($args[0], $args[1]);
					}
					else {
						$status = false;
					}
					break;
				}

				case 'ipam import':
				{
					if(count($args) === 2) {
						$status = $this->_PROGRAM->ipamImport($args[0], $args[1]);
					}
					else {
						$status = false;
					}
					break;
				}
				// --------------------------------------------------

				// ---------------------- RULE ----------------------
				case 'category': {
					$status = $this->_PROGRAM->rule_category($args);
					break;
				}
				case 'fullmesh': {
					$status = $this->_PROGRAM->rule_fullmesh($args);
					break;
				}
				case 'status': {
					$status = $this->_PROGRAM->rule_state($args);
					break;
				}
				case 'action': {
					$status = $this->_PROGRAM->rule_action($args);
					break;
				}
				case 'source host': {
					$status = $this->_PROGRAM->rule_source(Core\Api_Host::OBJECT_TYPE, $args);
					break;
				}
				case 'source subnet': {
					$status = $this->_PROGRAM->rule_source(Core\Api_Subnet::OBJECT_TYPE, $args);
					break;
				}
				case 'source network': {
					$status = $this->_PROGRAM->rule_source(Core\Api_Network::OBJECT_TYPE, $args);
					break;
				}
				case 'destination host': {
					$status = $this->_PROGRAM->rule_destination(Core\Api_Host::OBJECT_TYPE, $args);
					break;
				}
				case 'destination subnet': {
					$status = $this->_PROGRAM->rule_destination(Core\Api_Subnet::OBJECT_TYPE, $args);
					break;
				}
				case 'destination network': {
					$status = $this->_PROGRAM->rule_destination(Core\Api_Network::OBJECT_TYPE, $args);
					break;
				}
				case 'protocol': {
					$status = $this->_PROGRAM->rule_protocol(Core\Api_Protocol::OBJECT_TYPE, $args);
					break;
				}
				case 'description': {
					$status = $this->_PROGRAM->rule_description($args);
					break;
				}
				case 'tag': {
					$status = $this->_PROGRAM->rule_tag(Core\Api_Tag::OBJECT_TYPE, $args);
					break;
				}
				case 'tags': {
					$status = $this->_PROGRAM->rule_tags(Core\Api_Tag::OBJECT_TYPE, $args);
					break;
				}
				case 'check': {
					$status = $this->_PROGRAM->rule_check();
					break;
				}
				case 'reset': {
					$status = $this->_PROGRAM->rule_reset();
					break;
				}
				case 'reset source host': {
					$status = $this->_PROGRAM->rule_reset('source', Core\Api_Host::OBJECT_TYPE, $args);
					break;
				}
				case 'reset source subnet': {
					$status = $this->_PROGRAM->rule_reset('source', Core\Api_Subnet::OBJECT_TYPE, $args);
					break;
				}
				case 'reset source network': {
					$status = $this->_PROGRAM->rule_reset('source', Core\Api_Network::OBJECT_TYPE, $args);
					break;
				}
				case 'reset destination host': {
					$status = $this->_PROGRAM->rule_reset('destination', Core\Api_Host::OBJECT_TYPE, $args);
					break;
				}
				case 'reset destination subnet': {
					$status = $this->_PROGRAM->rule_reset('destination', Core\Api_Subnet::OBJECT_TYPE, $args);
					break;
				}
				case 'reset destination network': {
					$status = $this->_PROGRAM->rule_reset('destination', Core\Api_Network::OBJECT_TYPE, $args);
					break;
				}
				case 'reset protocol': {
					$status = $this->_PROGRAM->rule_reset('protocol', Core\Api_Protocol::OBJECT_TYPE, $args);
					break;
				}
				case 'reset tag': {
					$status = $this->_PROGRAM->rule_reset('tag', Core\Api_Tag::OBJECT_TYPE, $args);
					break;
				}
				case 'reset sources': {
					$status = $this->_PROGRAM->rule_reset('sources');
					break;
				}
				case 'reset destinations': {
					$status = $this->_PROGRAM->rule_reset('destinations');
					break;
				}
				case 'reset protocols': {
					$status = $this->_PROGRAM->rule_reset('protocols');
					break;
				}
				case 'reset tags': {
					$status = $this->_PROGRAM->rule_reset('tags');
					break;
				}
				case 'exit':
				case 'quit':
				{
					$exitRule = $this->_PROGRAM->rule_exit();

					if(!$exitRule)
					{
						if(!$this->_PROGRAM->hasChanges() || (isset($args[0]) && $args[0] === 'force')) {
							$exit = parent::_routeShellCmd($cmd, $args);
						}
						else {
							$this->error("Vous n'avez pas sauvegardé la configuration, si vous souhaitez réellement quitter utilisez l'argument 'force'", 'orange');
						}
					}
					break;
				}
				// --------------------------------------------------

				// --------------------- CONFIG ---------------------
				case 'load':
				{
					$status = $this->_PROGRAM->load($args);
					break;
				}
				case 'run':
				{
					$status = $this->_PROGRAM->run($args);
					break;
				}
				case 'save':
				{
					$status = $this->_PROGRAM->save($args);
					break;
				}
				case 'import configuration':
				{
					$status = $this->_PROGRAM->import(null, $args);
					break;
				}
				case 'export configuration':
				{
					$status = $this->_PROGRAM->export(null, $args);
					break;
				}
				/*case 'export hosts':
				{
					$status = $this->_PROGRAM->export(Core\Api_Host::OBJECT_TYPE, $args);
					break;
				}
				case 'export subnets':
				{
					$status = $this->_PROGRAM->export(Core\Api_Subnet::OBJECT_TYPE, $args);
					break;
				}
				case 'export networks':
				{
					$status = $this->_PROGRAM->export(Core\Api_Network::OBJECT_TYPE, $args);
					break;
				}*/
				case 'export rules':
				{
					$status = $this->_PROGRAM->export(Core\Api_Rule::OBJECT_TYPE, $args);
					break;
				}
				case 'copy configuration':
				{
					$status = $this->_PROGRAM->copy(null, $args);
					break;
				}
				// --------------------------------------------------

				// -------------------- FIREWALL --------------------
				case 'firewall':
				{
					if(isset($args[0]))
					{
						if(isset($this->_sites->{$args[0]}))
						{
							$Site = $this->_sites->{$args[0]};

							$ip = $Site->ip;
							$hostname = $Site->hostname;
							$guiProtocol = $Site->getGuiProtocol();
							$guiAddress = $Site->getGuiAddress();

							switch($guiProtocol)
							{
								case 'http':
								case 'https': {
									$address = ($guiAddress !== false) ? ($guiAddress) : ($guiProtocol.'://'.$ip);
									$cmd = $this->_CONFIG->DEFAULT->sys->browserCmd;
									break;
								}
								case 'jnlp':
								case 'java':
								case 'javaws':
								{
									// @todo configurable
									$jnlpFilename = ROOT_DIR ."/tmp/".$hostname.".jnlp";

									if(!file_exists($jnlpFilename))
									{
										$jnlpUrl = ($guiAddress !== false) ? ($guiAddress) : ($Site->jnlp);

										// @todo configurable
										$options = array(
											"ssl" => array(
												"verify_peer" => false,
												"verify_peer_name" => false
											)
										);

										$context = stream_context_create($options);
										$ressource = fopen($jnlpUrl, 'r', false, $context);
										$status = file_put_contents($jnlpFilename, $ressource);

										if($status === false) {
											$this->error("Impossible de télécharger le JNLP [".$jnlpUrl."]", 'red');
											break;
										}
									}

									$address = $jnlpFilename;
									$cmd = $this->_CONFIG->DEFAULT->sys->javawsCmd;
									break;
								}
								case 'ssh': {
									$address = ($guiAddress !== false) ? ($guiAddress) : ($ip);
									$cmd = $this->_CONFIG->DEFAULT->sys->secureShellCmd;
									break;
								}
								default: {
									throw new Exception("Remote GUI protocol '".$guiProtocol."' is not allowed", E_USER_ERROR);
								}
							}

							$this->deleteWaitingMsg();
							$handle = popen($cmd.' "'.$address.'" > /dev/null 2>&1', 'r');
							pclose($handle);
						}
						else {
							$this->error("Le site '".$args[0]."' n'existe pas", 'orange');
						}

						$status = true;
					}
					else {
						$status = false;
					}

					break;
				}
				// --------------------------------------------------
				default: {
					$exit = parent::_routeShellCmd($cmd, $args);
				}
			}

			if(isset($status)) {
				$this->_routeShellStatus($cmd, $status);
			}

			return $exit;
		}
	}