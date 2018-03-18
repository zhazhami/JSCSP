function geturlpath(url){
    if(url.indexOf('?') != -1)return url.split('?')[0];
    else return url;
}
chrome.tabs.getSelected(null, function (tab) {
    url = tab.url;
    if(JSON.parse(localStorage['jscsp_policy']).hasOwnProperty(url)){
        $('.p-status').html("This page has policies.");
    }
    else{
        $('.p-status').html("This page has no policy.");
    }
});
var isblock = document.getElementById("isblock");
var isblock2 = document.getElementById("isblock2");
isblock2.checked = Number(localStorage['isblock']);

isblock.onchange=function(){
    localStorage['isblock'] = Number(isblock2.checked);
}

$('#gen_policy').click(function(){
    //chrome.tabs.executeScript({file:"js/gen_policy.js", allFrames:true});
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs){  
        chrome.tabs.sendMessage(tabs[0].id, {cmd:"gen_policy"}, function(response) {
        });
    });
});