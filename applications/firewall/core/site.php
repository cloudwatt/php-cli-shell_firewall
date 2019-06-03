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
			$guiProtocol = $this->getGuiProtocol();

			if($this->_datasObject->key_exists($guiProtocol)) {
				return $this->_datasObject[$guiProtocol];
			}
			else {
				return false;
			}
		}
	}