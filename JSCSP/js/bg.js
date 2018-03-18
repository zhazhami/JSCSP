var url_pattern = /^((?:https?|ftp|file):\/\/[A-Za-z0-9&@\-#%?=~_|!:.]+)[\/-A-Za-z0-9+&@#%=~_|]/;
if (localStorage.getItem('jscsp_policy') == null) {
    localStorage.setItem('jscsp_policy', '{}');
}

chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
    if (message.cmd == 'set_status') {
        localStorage.status = message.value;
    }
    else if (message.cmd == 'get_status') {
        if (!localStorage.status) {
            localStorage.status = 'true';
        }
        ret = localStorage.status == 'true' ? true : false;
        sendResponse(ret);
    }
    else if (message.cmd == 'set_policy') {
        var url = sender.tab.url.split('#')[0];
        var url_policy = JSON.parse(message.value);
        var policy = JSON.parse(localStorage['jscsp_policy']);
        url_policy['request_src'] = JSON.parse(localStorage['rq_whitelists'])[url];
        for(var i in url_policy['element']){
            src = url_policy['element'][i]['src'];
            href = url_policy['element'][i]['href'];
            if(src)
            url_policy['request_src'] = url_policy['request_src'].concat(src);
            if(href)
            url_policy['request_src'] = url_policy['request_src'].concat(href);
        }
        policy[url] = JSON.stringify(url_policy);
        localStorage['jscsp_policy'] = JSON.stringify(policy);
        alert("Generation finished");
    }
    else if (message.cmd == 'get_policy') {
        var url = sender.tab.url.split('#')[0];
        ret = JSON.parse(localStorage['jscsp_policy'])[url];
        sendResponse(ret);
    }
    else if (message.cmd == 'get_rq_whitelists') {
        var url = sender.tab.url;
        ret = JSON.parse(localStorage['rq_whitelists'])[url];
        sendResponse(ret);
    }
});

/**************  Block Requests  **************/
var tabs = {};
localStorage['rq_whitelists'] = "{}";

// Get all existing tabs
chrome.tabs.query({}, function (results) {
    results.forEach(function (tab) {
        tabs[tab.id] = tab;
    });
});

// Create tab event listeners
function onUpdatedListener(tabId, changeInfo, tab) {
    tabs[tab.id] = tab;
}
function onRemovedListener(tabId) {
    delete tabs[tabId];
}

// Subscribe to tab events
chrome.tabs.onUpdated.addListener(onUpdatedListener);
chrome.tabs.onRemoved.addListener(onRemovedListener);

/* 
 * --------------------------------------------------
 * Request callback
 * --------------------------------------------------
 */
// Create request event listener
function onBeforeRequestListener(details) {
    if(!Number(localStorage['isblock']))return true;
    // *** Remember that tabId can be set to -1 ***
    var from_url = tabs[details.tabId].url;
    from_src = url_pattern.exec(from_url)[1];
    detail_src = url_pattern.exec(details.url)[1];
    if (from_src == detail_src) return true;
    var policy = JSON.parse(localStorage['jscsp_policy']);
    if (policy[from_url]) {
        var src = [];
        var request_src = JSON.parse(policy[from_url])["request_src"];
        if (request_src.indexOf(detail_src) == -1) {
            return { 'cancel': true };
        }
    }
    else {
        var rqlist = JSON.parse(localStorage['rq_whitelists']);
        if (details.type == "main_frame") {
            if (details.url != from_url) {
                if (!rqlist[details.url]) rqlist[details.url] = [details.url];
            }
            else {
                if (!rqlist[details.url]) rqlist[details.url] = [details.url];
            }
        }
        else {
            if (!rqlist[from_url]) rqlist[from_url] = [];
            if (rqlist[from_url].indexOf(detail_src) == -1) {
                rqlist[from_url].push(detail_src);
            }
        }
        localStorage['rq_whitelists'] = JSON.stringify(rqlist);
    }
    return true;
    // Respond to tab information
}

// Subscribe to request event
chrome.webRequest.onBeforeRequest.addListener(onBeforeRequestListener, {
    urls: ["<all_urls>"]
}, ["blocking"]);