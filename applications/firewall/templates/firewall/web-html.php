<?php
/**
  * /!\ La balise de fermeture de PHP '?>' supprime le saut de ligne qui la suit immédiatement
  * Un double saut de ligne est le workaround le plus simple à mettre en place
  */

	namespace App\Firewall;

	use App\Firewall\Core;

	$rules = $this->rules;

	foreach($rules as &$rule)
	{
		foreach(array('sources', 'destinations') as $attributes)
		{
			foreach($rule[$attributes] as &$attribute) {
				$attribute = $attribute['name'].' {'.$attribute['attributeV4'].'} ['.$attribute['attributeV6'].']';
			}
			unset($attribute);

			$rule[$attributes] = implode('<br />', $rule[$attributes]);
		}
	}
	unset($rule);
?>
<html>
	<head>
		<script src="https://cdn.jsdelivr.net/npm/handsontable@7.0.2/dist/handsontable.full.min.js"></script>
		<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/handsontable@7.0.2/dist/handsontable.full.min.css">
		<style type="text/css">
			#myGrid table.htCore thead tr th,
			#myGrid table.htCore tbody tr th {
				color: #cccccc;
				background: #626262;
				border-color: darkgrey;
			}

			#myGrid table.htCore tbody tr td.rowC1 {
				color: #cccccc;
				background: #403e3e;
			}

			#myGrid table.htCore tbody tr td.rowC2 {
				color: #cccccc;
				background: #302e2e;
			}

			#myGrid table.htCore tbody tr:hover td {
				color: black;
				background: #E9E9E9;
			}
		</style>
	</head>
	<body>
		<div id="myGrid"></div>
		<script type="text/javascript" charset="utf-8">
			var columnDefs = [
				{ title: 'Name', data: 'name', type: 'text' },
				{ title: 'Category', data: 'category', type: 'text' },
				{ title: 'Fullmesh', data: 'fullmesh', type: 'text' },
				{ title: 'State', data: 'state', type: 'text' },
				{ title: 'Action', data: 'action', type: 'text' },
				{ title: 'Source(s)', data: 'sources', type: 'text', renderer: 'html' },
				{ title: 'Destination(s)', data: 'destinations', type: 'text', renderer: 'html' },
				{ title: 'Protocol(s)', data: 'protocols', type: 'text', renderer: 'html' },
				{ title: 'Description', data: 'description', type: 'text' },
				{ title: 'Tags', data: 'tags', type: 'text' },
				{ title: 'Date/Time', data: 'date', type: 'text' }
			];

			var rowData = <?php echo json_encode(array_values($rules)); ?>

			var gridOptions = {
				columns: columnDefs,
				data: rowData,
				readOnly: true,
				//editor: false,
				allowEmpty: true,
				autoColumnSize: true,
				autoRowSize: false,
				rowHeights: '50px',
				copyPaste: true,
				filters: true,
				search: false,
				//columnSorting: true,
				multiColumnSorting: {
					initialConfig: {
						column: 1,
						sortOrder: 'asc'
					},
					indicator: true,
					headerAction: true,
					sortEmptyCells: true
				},
				manualRowResize: false,
				manualColumnResize: true,
				hiddenColumns: true,
				hiddenRows: true,
				dropdownMenu: true,
				contextMenu: ['copy', '---------', 'hidden_columns_hide', 'hidden_columns_show', 'hidden_rows_hide', 'hidden_rows_show', '---------'],
				allowInsertColumn: false,
				allowInsertRow: false,
				allowRemoveColumn: false,
				allowRemoveRow: false,
				
				stretchH: 'all',
				width: '100%',
				height: '100%',
				autoWrapCol: true,
				autoWrapRow: true,
				enterBeginsEditing: false,

				currentHeaderClassName: 'htCurHeader',
				activeHeaderClassName: 'htActHeader',
				currentRowClassName: 'htCurRow',
				currentColClassName: 'htCurCol',
				colHeaders: true,
				rowHeaders: false,
				//selectionMode: 'multiple',
				//outsideClickDeselects: false,
				cells: function (row, col) {
					var cellProperties = {};
					//var data = this.instance.getData();

					if(row % 2 === 0) {
						cellProperties.className = 'rowC1';
					}
					else {
						cellProperties.className = "rowC2";
					}

					return cellProperties;
				},
				renderAllRows: false,
				// Workaround
				/*tableClassName: 'htTableGrid',
				afterRowResize: function(currentRow, newSize, isDoubleClick)
				{
					var gridMasterTH = document.querySelectorAll('#myGrid div.ht_master table.htCore.htTableGrid')[0].querySelectorAll('tbody tr:nth-child('+(currentRow+1)+') th')[0];
					var gridCloneTH = document.querySelectorAll('#myGrid div.ht_clone_left table.htCore.htTableGrid')[0].querySelectorAll('tbody tr:nth-child('+(currentRow+1)+') th')[0];
					var thHeight = gridMasterTH.offsetHeight;
					gridCloneTH.style.height = thHeight+'px';
				},*/
				licenseKey: 'non-commercial-and-evaluation'
			};

			var eGridDiv = document.querySelector('#myGrid');
			var HT = new Handsontable(eGridDiv, gridOptions);

			/*var HtHeightWorkaround = function()
			{
				var gridMasterTH = document.querySelectorAll('#myGrid div.ht_master table.htCore.htTableGrid')[0].querySelectorAll('tbody tr th');

				gridMasterTH.forEach(function (element, index) {
					var thHeight = element.offsetHeight;
					var gridCloneTH = document.querySelectorAll('#myGrid div.ht_clone_left table.htCore.htTableGrid')[0].querySelectorAll('tbody tr:nth-child('+(index+1)+') th')[0];
					gridCloneTH.style.height = thHeight+'px';
				});
			};
			
			HtHeightWorkaround();*/
		</script>
	</body>
</html>