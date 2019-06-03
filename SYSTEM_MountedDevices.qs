//-----------------------------------------------------------
// SYSTEM_MountedDevices.qs
// Parse the SYSTEM hive file for mounted devices.
//
// Install: Copy file to report_templates directory
//
// Change history:
//    20190511 - created
//    20190603 - fixed linux issue
//
// References
//
// Author: Christian Hammer, christian_hammer@hotmail.com
//-----------------------------------------------------------
function fred_report_info() {
  var info={report_cat    : "SYSTEM",
            report_name   : "Mounted Devices",
            report_author : "Christian Hammer",
            report_desc   : "Report mounted devices",
            fred_api      : 2,
            hive          : "SYSTEM"
  };
  return info;
}

function fred_report_html() {
  var rootKey = "\\MountedDevices";

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

  var printroot =  "\\"+info.hive+rootKey;
  println("<div class='title'>"+info.report_name+"</div>");
  println("<div>Path: ",printroot,"</div>");

  // List installed applications
  var nodes = GetRegistryKeys(rootKey);
  if (!nodes) {
    rootKey = printroot = "\\"+info.hive+rootKey;
    nodes = GetRegistryKeys(rootKey);
  };

  if (!nodes) {
    println("<p><font color='red'>This registry hive contain no data!</font></p>");
    return;
  }

  println("<table>");
  println("<tr><td><b>Count</b></td><td>",nodes.length,"</td></tr>");
  for(var i=0;i<nodes.length;i++) {
    var path = GetRegistryKeyValue(rootKey,nodes[i]);
    // The path value comes in, at least, three falvours:
    // - An utf16 string
    // - An ascii (7/8-bit) string
    // - A Disk signature - LE 32-bit unsigned number.
    var strPath = "";
    if (path.value[2]==0x3f && path.value[4]==0x3f) // Unsafe check, but my best option right now.
      strPath = String(RegistryKeyValueToVariant(path.value, "utf16"));
    else if (path.length===12) // 32-bit signature and 64-bit byte offset. A somewhat unsafe check...
      strPath = "0x"+Number(RegistryKeyValueToVariant(path.value, "uint32")).toString(16)
              + ", offset=0x"+Number(RegistryKeyValueToVariant(path.value, "uint64",4,8)).toString(16)
    else
      strPath = String(RegistryKeyValueToVariant(path.value, "ascii"));
    // var encoding = "utf16"; //path.value[2]=='?'&&path.value[4]=='?') ? "acsii" : "utf16";
    // println("<tr><td>",nodes[i],"</td><td>", Number(path.value[2]).toString(16), ", ", Number(path.value[4]).toString(16), ", ", encoding, "</td></tr>");
    println("<tr><td>",nodes[i],"</td><td>",strPath,"</td></tr>");
  };

  println("</table></body></html>");
}

// Finally, call the main function - windows version of FRED does not run this automatically...
// While linux version need to postpone this to aftaer some initialisation!
if ("GetRegistryNodes" in this)
  fred_report_html();