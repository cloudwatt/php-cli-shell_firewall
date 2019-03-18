<?php
	namespace App\Firewall\Core;

	use Core as C;

	class Site extends C\Item
	{
		public function getGuiProtocol()
		{
			return $this->_datasObject['gui'];
		}

		public function getGuiAddress()
		{
			return $this->_datasObject['ip'];
		}
	}