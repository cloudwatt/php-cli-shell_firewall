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

			//$rule[$attributes] = implode('<br />', $rule[$attributes]);
		}
	}
	unset($rule);
?>
<html>
	<head>
		<script src="https://unpkg.com/ag-grid-community/dist/ag-grid-community.min.noStyle.js"></script>
		<link rel="stylesheet" href="https://unpkg.com/ag-grid-community/dist/styles/ag-grid.css">
		<link rel="stylesheet" href="https://unpkg.com/ag-grid-community/dist/styles/ag-theme-dark.css">
		<style type="text/css">
			/*.ag-row.ag-row-no-focus.rowC1:not(.ag-row-hover) {
				background: #E9E9E9;
			}

			.ag-row.ag-row-no-focus.rowC2:not(.ag-row-hover) {
				background: #D4D4D4;
			}*/

			.ag-row.ag-row-hover {
				color: black;
				background: #E9E9E9;
			}
		</style>
	</head>
	<body>
		<div id="myGrid" style="height:100%;width:100%;" class="ag-theme-dark"></div>
		<script type="text/javascript" charset="utf-8">
			// specify the columns
			var columnDefs = [
				{headerName: "Name", field: "name", sortable: true, filter: true},
				{headerName: "Category", field: "category", sortable: true, filter: true},
				{headerName: "Fullmesh", field: "fullmesh", sortable: true, filter: true},
				{headerName: "State", field: "state", sortable: true, filter: true},
				{headerName: "Action", field: "action", sortable: true, filter: true},
				{headerName: "Source(s)", field: "sources", sortable: true, filter: true, resizable: true, autoHeight: true,
					cellRenderer: function(param) {
						return param.data.sources.join('<br />');
					}
				},
				{headerName: "Destination(s)", field: "destinations", sortable: true, filter: true, resizable: true, autoHeight: true,
					cellRenderer: function(param) {
						return param.data.destinations.join('<br />');
					}
				},
				{headerName: "Protocol(s)", field: "protocols", sortable: true, filter: true, resizable: true, autoHeight: true,
					cellRenderer: function(param) {
						return param.data.protocols.join('<br />');
					}
				},
				{headerName: "Description", field: "description", sortable: true, filter: true, resizable: true},
				{headerName: "Tags", field: "tags", sortable: true, filter: true, resizable: true,
					cellRenderer: function(param) {
						return param.data.tags.join(' ');
					}
				},
				{headerName: "Date/Time", field: "date", sortable: true, filter: true}
			];

			 // specify the data
			var rowData = <?php echo json_encode(array_values($rules)); ?>

			// let the grid know which columns and what data to use
			var gridOptions = {
				columnDefs: columnDefs,
				rowData: rowData
			};

			gridOptions.getRowClass = function(params) {
				if(params.node.rowIndex % 2 === 0) {
					return 'rowC1';
				}
				else {
					return 'rowC2';
				}
			};

			// lookup the container we want the Grid to use
			var eGridDiv = document.querySelector('#myGrid');

			// create the grid passing in the div to use together with the columns & data we want to use
			new agGrid.Grid(eGridDiv, gridOptions);

			function autoSizeAll() {
				var allColumnIds = [];
					gridOptions.columnApi.getAllColumns().forEach(function(column) {
					allColumnIds.push(column.colId);
				});
				gridOptions.columnApi.autoSizeColumns(allColumnIds);
			}

			autoSizeAll();
		</script>
	</body>
</html>