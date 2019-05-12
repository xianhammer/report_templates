//-----------------------------------------------------------
// SYSTEM_UsbDevices.qs
// Parse the SYSTEM hive file for USB devices.
//
// Install: Copy file to report_templates directory
//
// Change history:
//    20190511 - created
//
// References
//    http://www.forensicswiki.org/wiki/USB_History_Viewing
//    http://www.forensicmag.com/article/windows-7-registry-forensics-part-5
//
// Author: Christian Hammer, christian_hammer@hotmail.com
//-----------------------------------------------------------
function fred_report_info() {
  var info={report_cat    : "SYSTEM",
            report_name   : "USB devices",
            report_author : "Christian Hammer",
            report_desc   : "List known USB devices.",
            fred_api      : 2,
            hive          : "SYSTEM"
  };
  return info;
}

function get_currentControlSet(){
  var setID = GetRegistryKeyValue("\\Select","Current");
  return "\\ControlSet"+("000"+Number(RegistryKeyValueToVariant(setID.value, "uint32"))).substr(-3)+"\\";
};

var CONTEXT = this;
function get_string(path, name){
    var val = GetRegistryKeyValue(path,name);
    return val?RegistryKeyValueToString(val.value,val.type):undefined;
};

function get_modtime(path){
  var fnc = CONTEXT["GetRegistryNodeModTime"]; // Sometimes they come back...
  return fnc?fnc(path):undefined;
};

function fred_report_html() {
  var rootKey = get_currentControlSet();

  fred_report_html = function(){}; // Run only once. Trying to accomodate both windows and linux versions.
  var info = fred_report_info();

  println("<html><head>");
  // When copying from FRED to eg. word, some CSS attributes does not transfer properly - like most font information (especially in TD's).
  // Therefore, (some of) these are duplicated as html tags. SIGH!
  println("<style>");
  println("body, table {font-family: 'Courier New'; font-size: 12pt;}");
  println("*.title {font-size: 1.2em; font-weight: bold;}");
  println("td {vertical-align: top;}");
  println("td.title {padding-top: 0.5em;}");
  println("td:not(.title) {padding-left: 1em;}");
  println("div.title {font-size: 1.5em;}");
  println("</style>");
  println("</head><body>");

  var printroot = "\\"+info.hive+rootKey;
  println("<div class='title'>"+info.report_name+"</div>");
  println("<div>Path: ",printroot,"</div>");

  var start = GetRegistryKeyValue(rootKey+"\\services\\USBSTOR","Start");
  if (start) start = Number(RegistryKeyValueToVariant(start.value,"uint32"));

  var status = "Unknown";
  switch (start){
    case 3: status = "Yes"; break;
    case 4: status = "No"; break;
  };
  println("<div>Storage driver enabled: ",status,"</div>");

  // Preload MountedDevices to possibly identify mount points of USB storage devices
  // var mnt_keys = GetRegistryKeys("\\MountedDevices");
  // var mnt_values = new Array();
  // if(IsValid(mnt_keys)) {
  //   for(var i=0;i<mnt_keys.length;i++) {
  //     val = GetRegistryKeyValue("\\MountedDevices",mnt_keys[i]);
  //     mnt_values[i] = RegistryKeyValueToVariant(val.value,"utf16");
  //   }
  // }

  var usbstorKey = rootKey+"Enum\\USBSTOR\\";
  var nodes = GetRegistryNodes(usbstorKey);
  if (!nodes) {
    println("<p><font color='red'>This registry hive contain no data!</font></p>");
    return;
  }

  var keyPrefix = {"Ven": "Vendor", "Prod": "Product", "Rev": "Revision" };

  println("<table>");
  for (var i=0; i<nodes.length; ++i){
    var nodeKey = usbstorKey+nodes[i];
    println("<tr><td colspan='2'><b>", nodes[i], "</b></td></tr>");

    // Basic information (encoded in USB identifier string.)
    var parts = nodes[i].split(/&([^_]+)_/g);
    for (var j=1; j<parts.length; j+=2)
      println("<tr><td>", keyPrefix[parts[j]], "</td><td>", parts[j+1], "</td></tr>");

    // Extended information
    var usbIDs = GetRegistryNodes(nodeKey)||[];
    for (var j=0; j<usbIDs.length; ++j){
      var usbKey = nodeKey+"\\"+usbIDs[j];
      println("<tr><td>ID</td><td>", usbIDs[j], "</td></tr>");
      // We often have several more layers, first ["Device Parameters", "Properties"], ...

      println("<tr><td>Class</td><td>", get_string(usbKey,"Class") ,"</td></tr>");
      println("<tr><td>DeviceDesc</td><td>", get_string(usbKey,"DeviceDesc") ,"</td></tr>");
      println("<tr><td>FriendlyName</td><td>", get_string(usbKey,"FriendlyName") ,"</td></tr>");
      println("<tr><td>ParentIdPrefix</td><td>", get_string(usbKey,"ParentIdPrefix")||"" ,"</td></tr>");
      println("<tr><td>First connection</td><td>", get_modtime(nodeKey)||"","</td></tr>");
      println("<tr><td>Last connection</td><td>", get_modtime(usbKey)||"" ,"</td></tr>");
    };
  };
  println("</table>");
/*
      println("    <table style=\""+table_style+"\">");
      println("      <tr>");
      PrintTableHeaderCell("Vendor Name");
      PrintTableHeaderCell("Unique ID");
      PrintTableHeaderCell("Class");
      PrintTableHeaderCell("Friendly name");
      PrintTableHeaderCell("Mount point(s)");
      PrintTableHeaderCell("Parent ID");
      PrintTableHeaderCell("Device description");
      PrintTableHeaderCell("First connection<font color=\"red\"><sup>1</sup></font>");
      PrintTableHeaderCell("Last connection<font color=\"red\"><sup>1</sup></font>");
      println("      </tr>");

      for(var i=0;i<storage_roots.length;i++) {
        var storage_subroots=GetRegistryNodes(cur_controlset+"\\Enum\\USBSTOR\\"+storage_roots[i]);
        for(var ii=0;ii<storage_subroots.length;ii++) {
          var device_id=storage_subroots[ii];
          if(String(device_id).charAt(1)=="&") {
            // If the second character of the unique instance ID is a '&', then
            // the ID was generated by the system, as the device did not have a
            // serial number.
            device_id=device_id+" (Generated by system)";
          }

          var device_key=cur_controlset+"\\Enum\\USBSTOR\\"+storage_roots[i]+"\\"+storage_subroots[ii];
          var device_class=GetKeyVal(device_key,"Class");
          var device_desc=GetKeyVal(device_key,"DeviceDesc");
          var device_friendly_name=GetKeyVal(device_key,"FriendlyName");
          var device_parent_id=GetKeyVal(device_key,"ParentIdPrefix");
          var device_first_connection=GetRegistryNodeModTime(cur_controlset+"\\Enum\\USBSTOR\\"+storage_roots[i]);
          var device_last_connection=GetRegistryNodeModTime(cur_controlset+"\\Enum\\USBSTOR\\"+storage_roots[i]+"\\"+storage_subroots[ii]);

          var search_string="";
          var device_mount_points=Array();
          if(device_parent_id != "") {
            // Windows XP uses the ParentId to link to MountedDevices
            search_string="#"+device_parent_id+"&";
          } else {
            // Since Vista, Unique IDs are used
            search_string="#"+storage_subroots[ii]+"#";
          }
          for(var iii=0; iii<mnt_keys.length; iii++) {
            if(String(mnt_values[iii]).indexOf(search_string)!=-1) {
              device_mount_points.push(mnt_keys[iii]);
            }
          }

          var mount_points=device_mount_points.length;
          if(mount_points>1) {
            println("      <tr>");
            PrintTableDataRowSpanCell("left",mount_points,storage_roots[i]);
            PrintTableDataRowSpanCell("left",mount_points,device_id);
            PrintTableDataRowSpanCell("left",mount_points,device_class);
            PrintTableDataRowSpanCell("left",mount_points,device_friendly_name);
            PrintTableDataCell("left",device_mount_points[0]);
            PrintTableDataRowSpanCell("left",mount_points,device_parent_id);
            PrintTableDataRowSpanCell("left",mount_points,device_desc);
            PrintTableDataRowSpanCell("left",mount_points,device_first_connection);
            PrintTableDataRowSpanCell("left",mount_points,device_last_connection);
            println("      </tr>");
            for(var iii=1;iii<device_mount_points.length;iii++) {
              println("      <tr>");
              PrintTableDataCell("left",device_mount_points[iii]);
              println("      </tr>");
            }
          } else {
            println("      <tr>");
            PrintTableDataCell("left",storage_roots[i]);
            PrintTableDataCell("left",device_id);
            PrintTableDataCell("left",device_class);
            PrintTableDataCell("left",device_friendly_name);
            if(mount_points!=0) {
              PrintTableDataCell("left",device_mount_points[0]);
            } else {
              PrintTableDataCell("left","n/a");
            }
            PrintTableDataCell("left",device_parent_id);
            PrintTableDataCell("left",device_desc);
            PrintTableDataCell("left",device_first_connection);
            PrintTableDataCell("left",device_last_connection);
            println("      </tr>");
          }
        }
      }
      println("    </table>");
      println("    &nbsp;&nbsp;&nbsp;&nbsp;<font color=\"red\"><sup>1</sup></font> Might be incorrect");
    println("  </p>");
  }
  */
}

fred_report_html();