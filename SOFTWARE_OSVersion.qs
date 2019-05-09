//-----------------------------------------------------------
// SOFTWARE_OSVersion.qs
// Parse the SOFTWARE hive file for OS Version information
//
// Install: Copy file to report_templates directory
//
// Change history:
//    20190509 - created
//
// References
//
// Author: Christian Hammer, christian_hammer@hotmail.com
//-----------------------------------------------------------
function fred_report_info() {
  var info={report_cat    : "SOFTWARE",
            report_name   : "OS Version",
            report_author : "Christian Hammer",
            report_desc   : "Dump OS Version",
            fred_api      : 2,
            hive          : "SOFTWARE"
  };
  return info;
}

function fred_report_html() {
  var rootKey = "\\Microsoft\\Windows NT\\CurrentVersion";

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

  var keys = GetRegistryKeys(rootKey);
  if (!keys) {
    rootKey = printroot = "\\"+info.hive+rootKey;
    keys = GetRegistryKeys(rootKey);
  };

  if (!keys) {
    println("<p><font color='red'>This registry hive contain no data!</font></p>");
    return;
  }

  println("<table>");
  for(var i=0;i<keys.length;i++) {
    var val = GetRegistryKeyValue(rootKey, keys[i]);
    switch (val.type){
    case 3:
        println("<tr><td>", keys[i], "</td><td>Binary - not decoded</td></tr>");
        continue;
    default:
        break;
    };

    var strOut = RegistryKeyValueToString(val.value,val.type);
    switch (keys[i]){
      case "InstallDate":
        strOut = RegistryKeyValueToVariant(val.value,"unixtime")+" ("+strOut+")";
        break;
      case "InstallTime":
        strOut = RegistryKeyValueToVariant(val.value,"filetime")+" ("+strOut+")";
        break;
      default:
        // strOut = RegistryKeyValueToString(val.value,val.type);
        break;
    }
    println("<tr><td>", keys[i], "</td><td>", strOut, "</td></tr>");
  }

  println("</table></body></html>");
}

fred_report_html();
