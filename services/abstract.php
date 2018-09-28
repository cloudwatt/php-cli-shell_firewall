<?php
	require_once(__DIR__ . '/../classes/tools.php');
	require_once(__DIR__ . '/../classes/config.php');
	require_once(__DIR__ . '/../shell/abstract.php');

	abstract class Service_Abstract
	{
		const PHP_MIN_VERSION = '7.1.14';

		const CLI_OPTION_DELIMITER = ';';

		protected $_CONFIG;

		protected $_SHELL;
		protected $_Service_Shell;

		protected $_commands = array();

		/**
		  * Arguments ne commencant pas par - mais étant dans le flow de la commande
		  *
		  * ls mon/chemin/a/lister
		  * cd mon/chemin/ou/aller
		  * find ou/lancer/ma/recherche
		  */
		protected $_inlineArgCmds = array();

		/**
		  * Arguments commencant pas par - ou -- donc hors flow de la commande
		  *
		  * find ... -type [type] -name [name]
		  */
		protected $_outlineArgCmds = array();

		/**
		  * /!\ Ordre important
		  *
		  * L'ordre des commandes ci-dessous sera respecté
		  * afin que la configuration soit valide
		  */
		protected $_cliOptions = array();

		protected $_cliToCmd = array();

		protected $_manCommands = array();

		protected $_waitingMsgFeature = true;
		protected $_waitingMsgState = false;

		protected $_isOneShotCall = null;
		protected $_lastCmdResult = null;
		protected $_lastCmdStatus = null;

		protected $_debug = false;


		public function __construct($configFilename)
		{
			set_error_handler(array(static::class, 'errorHandler'));

			if(version_compare(PHP_VERSION, self::PHP_MIN_VERSION) === -1) {
				throw new Exception("Version PHP inférieure à ".self::PHP_MIN_VERSION.", PHP ".self::PHP_MIN_VERSION." min requis", E_USER_ERROR);
			}

			$debug = getenv('PHPCLISHELL_DEBUG');

			if(mb_strtolower($debug) === "true") {
				$this->_debug = (bool) $debug;
			}

			$this->_CONFIG = CONFIG::getInstance();
			$this->_CONFIG->loadConfigurations($configFilename, false);

			$this->_SHELL = new SHELL($this->_commands, $this->_inlineArgCmds, $this->_outlineArgCmds, $this->_manCommands);
			$this->_SHELL->debug($this->_debug)->setHistoryFilename(static::SHELL_HISTORY_FILENAME);
		}

		public function test($cmd, array $args = array())
		{
			$this->_isOneShotCall = true;
			$this->waitingMsgFeature(false);
			$this->_preLauchingShell(false);

			$this->_preRoutingShellCmd($cmd, $args);
			$exit = $this->_routeShellCmd($cmd, $args);
			$this->_postRoutingShellCmd($cmd, $args);

			echo json_encode($this->_lastCmdResult);

			$this->_postLauchingShell(false);
		}

		protected function _init()
		{
			$this->_oneShotCall();

			$this->_preLauchingShell();
			$this->_launchShell();
			$this->_postLauchingShell();

			return $this;
		}

		public function isOneShotCall()
		{
			if($this->_isOneShotCall === null) {
				$this->_isOneShotCall = ($_SERVER['argc'] > 1);
			}

			return $this->_isOneShotCall;
		}

		protected function _oneShotCall()
		{
			if($this->isOneShotCall())
			{
				$this->waitingMsgFeature(false);
				$this->_preLauchingShell(false);

				if($_SERVER['argc'] === 2)
				{
					$cmd = $_SERVER['argv'][1];
					$status = $this->_routeCliCmdCall($cmd);

					if($status) {
						echo json_encode($this->_lastCmdResult);
						$exitCode = 0;
					}
					else {
						$this->error("Commande invalide", 'red', false, 'bold');
						$this->_SHELL->help();
						$exitCode = 1;
					}
				}
				else {
					$exitCode = $this->_dispatchCliCall();
				}

				$this->_postLauchingShell(false);
				exit($exitCode);
			}
		}

		protected function _dispatchCliCall()
		{
			$this->_isOneShotCall = false;
			$this->waitingMsgFeature(true);

			$options = getopt($this->_cliOptions['short'], $this->_cliOptions['long']);

			// Permet de garantir l'ordre d'exécution des commandes
			foreach($this->_cliOptions['long'] as $cli)
			{
				$cli = str_replace(':', '', $cli);

				if(isset($options[$cli]))
				{
					$option = (array) $options[$cli];

					foreach($option as $_option)
					{
						$status = $this->_cliOptToCmdArg($cli, $_option);

						if(!$status) {
							return 1;
						}
					}
				}
			}

			return 0;
		}

		protected function _cliOptToCmdArg($cli, $option)
		{
			return 1;
		}

		protected function _routeCliCmdCall($cmd)
		{
			$Shell_Autocompletion = new Shell_Autocompletion($this->_commands, $this->_inlineArgCmds, $this->_outlineArgCmds, $this->_manCommands);
			$Shell_Autocompletion->debug($this->_debug);

			$status = $Shell_Autocompletion->_($cmd);

			if($status)
			{
				$cmd = $Shell_Autocompletion->command;
				$args = $Shell_Autocompletion->arguments;

				$this->_preRoutingShellCmd($cmd, $args);
				$this->_routeShellCmd($cmd, $args);
				$this->_postRoutingShellCmd($cmd, $args);
				return $this->_lastCmdStatus;
			}
			else {
				return false;
			}
		}

		protected function _preLauchingShell($welcomeMessage = true)
		{
			if($welcomeMessage) {
				$this->EOL();
				$this->print("CTRL+C ferme le shell, utilisez ALT+C à la place", 'blue', false, 'italic');
				$this->print("Utilisez UP et DOWN afin de parcourir votre historique de commandes", 'blue', false, 'italic');
				$this->print("Utilisez TAB pour l'autocomplétion et ? afin d'obtenir davantage d'informations", 'blue', false, 'italic');
				$this->EOL();
			}
		}

		abstract protected function _launchShell();

		protected function _postLauchingShell($goodbyeMessage = true)
		{
			if($goodbyeMessage) {
				$this->EOL();
				$this->print("Merci d'avoir utilisé TOOLS-CLI by NOC", 'blue', false, 'italic');
				$this->EOL();
			}
		}

		protected function _preRoutingShellCmd(&$cmd, array &$args)
		{
			/**
			  * Dans certains cas, un espace peut être autocomplété à la fin de la commande afin de faciliter à l'utilisateur la CLI.
			  * Exemple: show => array('host', 'subnet') --> "show " afin que l'utilisateur puisse poursuivre la commande
			  *
			  * Cependant, si l'on souhaite autoriser "show" comme commande valide alors il faut nettoyer l'autocompletion
			  *
			  * Ce traitement est à réaliser pour les commandes OneShot, CLI et SHELL.
			  * De ce fait il ne faut pas le réaliser dans Shell_Abstract sinon les commandes OneShot ne seront pas nettoyées
			  */
			$cmd = rtrim($cmd, ' ');

			foreach($args as &$arg) {
				$arg = preg_replace('#^("|\')|("|\')$#i', '', $arg);
			}

			$this->displayWaitingMsg(false, false);
		}

		protected function _routeShellCmd($cmd, array $args)
		{
			switch($cmd)
			{
				case '': {
					$this->print("Tape help for help !", 'blue');
					break;
				}
				case 'history': {
					$this->deleteWaitingMsg();
					$this->_SHELL->history();
					$this->EOL();
					break;
				}
				case 'help': {
					$this->deleteWaitingMsg();
					$this->_SHELL->help();
					$this->EOL();
					break;
				}
				case 'exit':
				case 'quit': {
					$this->deleteWaitingMsg();
					return true;
				}
				default: {
					$this->error("Commande inconnue... [".$cmd."]", 'red');
				}
			}

			return false;
		}

		protected function _postRoutingShellCmd($cmd, array $args) {}

		public function displayWaitingMsg($startEOL = true, $finishEOL = false, $infos = null)
		{
			if($this->waitingMsgFeature() && !$this->_waitingMsgState)
			{
				/**
				  * /!\ Ne pas inclure les sauts de lignes dans le traitement de la police
				  * $infos ne doit pas contenir de saut de lignes sinon la desactivation ne fonctionnera pas complètement
				  */
				$message = ($startEOL) ? (PHP_EOL) : ('');

				$message .= Tools::e("Veuillez patienter ...", 'orange', false, 'bold', true);
				if($infos !== null) { $message .= Tools::e(' ('.$infos.')', 'orange', false, 'bold', true); }

				if($finishEOL) { $message .= PHP_EOL; }
				$this->_SHELL->insertMessage($message);
				$this->_waitingMsgState = true;
				return true;
			}
			else {
				return false;
			}
		}

		public function deleteWaitingMsg($lineUP = true)
		{
			if($this->waitingMsgFeature() && $this->_waitingMsgState) {
				$this->_SHELL->deleteMessage(1, $lineUP);
				$this->_waitingMsgState = false;
				return true;
			}
			else {
				return false;
			}
		}

		public function waitingMsgFeature($status = null)
		{
			if($status === true || $status === false) {
				$this->_waitingMsgFeature = $status;
			}
			return $this->_waitingMsgFeature;
		}

		public function setLastCmdResult($result)
		{
			$this->_lastCmdResult = $result;
			return $this;
		}

		protected function _e($text, $textColor = false, $bgColor = false, $textStyle = false, $doNotPrint = false)
		{
			return ($this->_isOneShotCall) ? ($text) : (Tools::e($text, $textColor, $bgColor, $textStyle, $doNotPrint));
		}

		public function format($text, $textColor = 'green', $bgColor = false, $textStyle = false)
		{
			return $this->_e($text, $textColor, $bgColor, $textStyle, true);
		}

		public function EOL($multiplier = 1, $textColor = false, $bgColor = false, $textStyle = false, $autoDelWaitingMsg = true)
		{
			if($autoDelWaitingMsg) {
				$this->deleteWaitingMsg();
			}

			$this->_e(str_repeat(PHP_EOL, $multiplier), $textColor, $bgColor, $textStyle, false);
			return $this;	// /!\ Important
		}

		public function print($text, $textColor = 'green', $bgColor = false, $textStyle = false, $autoDelWaitingMsg = true)
		{
			if($autoDelWaitingMsg) {
				$this->deleteWaitingMsg();
			}

			/** 
			  * /!\ Ne doit pas être formaté comme le texte
			  * /!\ Ne pas supprimer le message d'attente:
			  * - Déjà traité dans cette méthode
			  * - Si $autoDelWaitingMsg === false
			  */
			$this->EOL(1, false, false, false, false);
			return $this->_e($text, $textColor, $bgColor, $textStyle, false);
		}

		public function error($text, $textColor = 'red', $bgColor = false, $textStyle = false, $autoDelWaitingMsg = true)
		{
			if($autoDelWaitingMsg) {
				$this->deleteWaitingMsg();
			}

			/** 
			  * /!\ Ne doit pas être formaté comme le texte
			  * /!\ Ne pas supprimer le message d'attente:
			  * - Déjà traité dans cette méthode
			  * - Si $autoDelWaitingMsg === false
			  */
			$this->EOL(1, false, false, false, false);
			return $this->_e($text, $textColor, $bgColor, $textStyle, false);
		}

		protected function _throwException(Exception $exception)
		{
			Tools::e(PHP_EOL.PHP_EOL."Exception --> ".$exception->getMessage()." [".$exception->getFile()."] {".$exception->getLine()."}", 'red');
		}

		public static function errorHandler($errno, $errstr, $errfile, $errline)
		{
			throw new ErrorException($errstr, 0, $errno, $errfile, $errline);
		}
	}