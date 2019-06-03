<?php
	namespace App\Firewall\Core;

	use Core as C;
	use Core\Exception as E;

	use Cli as Cli;

	abstract class Template_Abstract
	{
		const OBJECT_TYPE_SECTION = array(
			Api_Host::OBJECT_TYPE => 'hosts',
			Api_Subnet::OBJECT_TYPE => 'subnets',
			Api_Network::OBJECT_TYPE => 'networks',
			Api_Rule::OBJECT_TYPE => 'rules'
		);

		const SECTION_TYPE_VAR = array(
			'hosts' => 'hosts',
			'subnets' => 'subnets',
			'networks' => 'networks',
			'rules' => 'rules'
		);

		/**
		  * @var Cli\Shell\Main
		  */
		protected $_SHELL;

		/**
		  * @var App\Firewall\Core\Api_Site[]
		  */
		protected $_sites;

		/**
		  * @var App\Firewall\Core\Firewall
		  */
		protected $_firewall;

		/**
		  * @var App\Firewall\Core\Site
		  */
		protected $_site;

		/**
		  * @var App\Firewall\Core\Api_Site
		  */
		protected $_siteApi;

		/**
		  * Script filename
		  * @var string
		  */
		protected $_script;

		/**
		  * Export filename
		  * @var string
		  */
		protected $_export;

		/**
		  * Debug mode
		  * @var bool
		  */
		protected $_debug = false;


		/**
		  * @param Shell\Service\Main $SHELL
		  * @param App\Firewall\Core\Api_Site[] $sites
		  * @return $this
		  */
		public function __construct(Cli\Shell\Main $SHELL, array $sites)
		{
			$this->_SHELL = $SHELL;

			$this->_sites = $sites;
		}

		/**
		  * @param Firewall $firewall
		  * @param array $sections
		  * @return bool
		  */
		public function templating(Firewall $firewall, array $sections)
		{
			$this->_firewall = $firewall;
			$this->_site = $firewall->site;

			$this->_script = $this->_getScript();
			$this->_export = $this->_getExport();

			$objects = array();

			foreach($sections as $section)
			{
				// @todo array objects a la place?? a voir
				if(array_key_exists($section, self::SECTION_TYPE_VAR)) {
					$varName = self::SECTION_TYPE_VAR[$section];
					$objects[$section] = $firewall->{$varName};
				}
			}

			return $this->_rendering($objects);
		}

		/**
		  * @return array Variables for rendering template
		  */
		protected function _getTemplateVars()
		{
			return array();
		}

		/**
		  * @param array $objects Current objects
		  * @return bool
		  */
		protected function _rendering(array $objects)
		{
			$sites = $this->_siteProcessing();
			$status = $this->_processing($sites, $objects);

			if($status)
			{
				$vars = $this->_getTemplateVars();

				try {
					$Core_Template = new C\Template($this->_script, $this->_export, $vars);
					$this->_script = $Core_Template->script;
					$this->_export = $Core_Template->export;
					return $Core_Template->rendering();
				}
				catch(E\Message $e) {
					$this->_SHELL->throw($e);
				}
				catch(\Exception $e) {
					$this->_SHELL->error($e->getMessage(), 'orange');
				}
			}

			return false;
		}

		/**
		  * Return all neighbour sites
		  *
		  * Current App\Firewall\Site is filtered
		  * Current App\Firewall\Core\Api_Site is registered
		  *
		  * @return App\Firewall\Core\Api_Site[] Sites
		  */
		protected function _siteProcessing()
		{
			$sites = $this->_sites;
			$this->_siteApi = null;

			// /!\ Doit travailler sur une copie
			foreach($sites as $index => $Api_Site)
			{
				if($Api_Site->name === $this->_site->name)
				{
					if($this->_siteApi === null) {
						$this->_siteApi = $Api_Site;
						unset($sites[$index]);
					}
					else {
						throw new Exception("The site '".$Api_Site->name."' is declared more than once", E_USER_ERROR);
					}
				}
			}

			if($this->_siteApi === null) {
				throw new Exception("The site '".$this->_site->name."' is is not declared", E_USER_ERROR);
			}

			return $sites;
		}

		/**
		  * @param App\Firewall\Core\Api_Site[] $sites
		  * @param array $objects
		  * @return bool
		  */
		protected function _processing(array $sites, array $objects)
		{
			return false;
		}

		/**
		  * @return string Script filename
		  */
		protected function _getScript()
		{
			$pathname = $this->_firewall->config->paths->templates;
			$script = rtrim($pathname, '/').'/'.static::VENDOR.'-'.static::PLATFORM;

			if(C\Tools::is('string&&!empty', static::TEMPLATE)) {
				$script .= '_'.static::TEMPLATE;
			}

			$script .= '.php';
			$firstChar = substr($script, 0, 1);

			if($firstChar !== '/' && $firstChar !== '~') {
				$script = APP_DIR.'/'.$script;
			}

			return $script;
		}

		/**
		  * @return string Export filename
		  */
		protected function _getExport()
		{
			$pathname = $this->_firewall->config->paths->exports;
			return rtrim($pathname, '/').'/'.$this->_site->hostname.'.'.static::TEMPLATE_EXT;
		}

		/**
		  * @param string $name
		  * @return mixed
		  * @throws Exception
		  */
		public function __get($name)
		{
			switch($name)
			{
				case 'firewall': {
					return $this->_firewall;
				}
				case 'site': {
					return $this->_site;
				}
				case 'siteApi': {
					return $this->_siteApi;
				}
				case 'script':
				case 'template': {
					return $this->_script;
				}
				case 'export': {
					return $this->_export;
				}
				default: {
					throw new Exception("This attribute '".$name."' does not exist", E_USER_ERROR);
				}
			}
		}
	}