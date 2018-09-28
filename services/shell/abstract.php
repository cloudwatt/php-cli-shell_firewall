<?php
	abstract class Service_Shell_Abstract
	{
		protected $_MAIN;
		protected $_SHELL;
		protected $_CONFIG;


		public function __construct(Service_Abstract $MAIN, SHELL $SHELL)
		{
			$this->_MAIN = $MAIN;
			$this->_SHELL = $SHELL;
			$this->_CONFIG = CONFIG::getInstance();
		}

		// @todo optimiser garder en cache en fonction de context
		abstract protected function _getObjects($context = null);

		/**
		  * Affiche les informations d'un seul type d'éléments ou d'objets
		  * Le code doit pouvoir fonctionner sur un tableau simple ou sur un tableau d'objets
		  */
		protected function _printInformations($type, $items, $title = false)
		{
			if($items !== false && Tools::is('array&&count>0', $items))
			{
				$results = array();

				if($title === false)
				{
					if(array_key_exists($type, $this->_PRINT_TITLES)) {
						$title = $this->_PRINT_TITLES[$type];
					}
					else {
						$title = 'INFORMATIONS';
					}
				}

				$this->_MAIN->EOL()->print($title, 'black', 'white', 'bold');

				/**
				  * /!\ item peut être un objet donc il faut que le code qui le concerne puisse fonctionner sur un objet
				  * Par exemple: array_key_exists ne peut pas fonctionner, mais isset oui grâce à __isset
				  */
				foreach($items as $index => $item)
				{
					/**
					  * Il faut réinitialiser $infos pour chaque item
					  * Permet aussi de garder l'ordre de _PRINT_FIELDS
					  */
					$infos = array();

					foreach($this->_PRINT_FIELDS[$type] as $key => $format)
					{
						// /!\ Code compatible array et object !
						if((is_array($item) && array_key_exists($key, $item)) || isset($item[$key]))
						{
							$field = $item[$key];
							$field = vsprintf($format, $field);

							switch($key)
							{
								case 'header':
									$field = $this->_MAIN->format($field, 'green', false, 'bold');
									break;
							}

							$infos[] = $field;
						}
					}

					if(count($infos) > 0) {
						$results[] = $infos;
						$this->_MAIN->EOL()->print(implode(PHP_EOL, $infos), 'grey');
					}
				}

				$this->_MAIN->EOL();
				$this->_MAIN->setLastCmdResult($results);
				return true;
			}
			else {
				$this->_MAIN->error("Aucun élément à afficher", 'orange');
			}

			return false;
		}

		abstract public function printObjectInfos(array $args, $fromCurrentContext = true);

		/**
		  * Récupère les informations d'un seul type d'éléments ou d'objets puis les affiche
		  * Le code doit pouvoir fonctionner sur un tableau simple ou sur un tableau d'objets
		  */
		protected function _printObjectInfos(array $cases, array $args, $fromCurrentContext = true)
		{
			if(isset($args[0]))
			{
				foreach($cases as $type => $method)
				{
					$objects = $this->{$method}($args[0], $fromCurrentContext);

					if(count($objects) > 0) {
						$objectType = $type;
						break;
					}
				}

				if(isset($objectType)) {
					$status = $this->_printInformations($objectType, $objects);
					return array($status, $objectType, $objects);
				}
			}

			$this->_MAIN->deleteWaitingMsg();		// Garanti la suppression du message
			return false;
		}

		/**
		  * Récupère les informations de tous les éléments ou objets puis les affiche
		  */
		public function printObjectsList($context = null)
		{
			$this->_MAIN->displayWaitingMsg();
			$objects = $this->_getObjects($context);
			return $this->_printObjectsList($objects);
		}

		/**
		  * Affiche les informations de plusieurs types d'éléments ou d'objets
		  * Le code doit pouvoir fonctionner sur un tableau simple ou sur un tableau d'objets
		  */
		protected function _printObjectsList(array $objects)
		{
			foreach($objects as $type => &$items)
			{
				if(count($items) > 0)
				{
					$this->_MAIN->EOL()->print($this->_LIST_TITLES[$type], 'black', 'white', 'bold');

					$items = Tools::arrayFilter($items, $this->_LIST_FIELDS[$type]['fields']);

					foreach($items as &$item)
					{
						/**
						  * /!\ L'ordre de base dans item est conservé ce qui rend le résultat incertain
						  * Préférer l'utilisation de la méthode Tools::arrayFilter qui filtre et garanti l'ordre
						  */
						//$item = array_intersect_key($item, array_flip($this->_LIST_FIELDS[$type]['fields']));

						$item = vsprintf($this->_LIST_FIELDS[$type]['format'], $item);

						$item = preg_replace_callback("#([^\t]*)(\t+)#i", function(array $matches) {
							return $matches[1].Tools::t($matches[1], "\t", mb_strlen($matches[2]), 0, 8);
						}
						, $item);
					}

					$this->_MAIN->EOL()->print(implode(PHP_EOL, $items), 'grey');
					$this->_MAIN->EOL();
				}
			}

			$this->_MAIN->deleteWaitingMsg();		// Garanti la suppression du message
			return $objects;
		}
	}