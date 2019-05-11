//-----------------------------------------------------------
// SOFTWARE_UninstalledApplications.qs
// Parse the SOFTWARE hive file for uninstalled applications.
//
// Install: Copy file to report_templates directory
//
// Change history:
//    20190511 - created
//
// References
//
// Author: Christian Hammer, christian_hammer@hotmail.com
//-----------------------------------------------------------
function fred_report_info() {
  var info={report_cat    : "SOFTWARE",
            report_name   : "Uninstalled Applications",
            report_author : "Christian Hammer",
            report_desc   : "Report uninstalled applications",
            fred_api      : 2,
            hive          : "SOFTWARE"
  };
  return info;
}

function fred_report_html() {
  var rootKey = "\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

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

  var nodes = GetRegistryNodes(rootKey);
  if (!nodes) {
    rootKey = printroot = "\\"+info.hive+rootKey;
    nodes = GetRegistryNodes(rootKey);
  };

  if (!nodes) {
    println("<p><font color='red'>This registry hive contain no data!</font></p>");
    return;
  }

  println("<table>");
  println("<tr><td><b>Count</b></td><td>",nodes.length,"</td></tr>");
  for(var i=0;i<nodes.length;i++) {
    // var path = GetRegistryKeyValue(rootKey,nodes[i]);
    var path = rootKey+"\\"+nodes[i];
    println("<tr><td colspan='2'><b>",nodes[i],"</b></td></tr>");
    println("<tr><td>Path</td><td>",path,"</td></tr>");

    var keys = GetRegistryKeys(path);
    for (var j=0; j<keys.length; ++j){
      var value = GetRegistryKeyValue(path, keys[j]);
      println("<tr><td>",keys[j],"</td><td>",RegistryKeyValueToString(value.value, value.type),"</td></tr>");
    };
  };
  println("</table></body></html>");
}

fred_report_html();