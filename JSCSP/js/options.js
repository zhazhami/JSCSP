var policies = JSON.parse(localStorage['jscsp_policy']);
for (url in policies) {
    $('#urls').append("<li><a href='#'>" + url + "</a></li>");
}
function  htmlDecode(value) {
    return  $('<div/>').html(value).text();
}
$('#urls li a').click(function () {
    $("#urls li").removeClass("active");
    $(this).parent().addClass("active");
    editor.set(JSON.parse(policies[htmlDecode($(this).html())]));
})

// create the editor
var container = document.getElementById("jsoneditor");
var options = {
    mode: 'code',
    indentation: '4'
};
var editor = new JSONEditor(container, options);

$('#save').click(function () {
    p = JSON.parse(localStorage['jscsp_policy']);
    p[$('#urls li.active a').text()] = JSON.stringify(editor.get());
    localStorage['jscsp_policy'] = JSON.stringify(p);
})

$('#delete').click(function () {
    p = JSON.parse(localStorage['jscsp_policy']);
    delete p[$('#urls li.active a').text()];
    localStorage['jscsp_policy'] = JSON.stringify(p);
    alert("Delete successfully!");
    location.reload();
})