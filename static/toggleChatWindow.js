$(document).ready(function(){
    report();
    ping_check();

    setInterval(report, 60000);
    setInterval(ping_check, 60000);

    function report(){
        $.post('/report', function(data) {
            console.log(data)
        });
    }
    
    function ping_check(){
        $.post('/pingCheck', function(data) {
            console.log(data)
        });
    }

    $("#changeStatusButton").click(function() {
        var selectedOption = $("#statusDropdown").children("option:selected").val();
        $("#statusLabel").text(selectedOption.charAt(0).toUpperCase() + selectedOption.slice(1));
        $.post('/statusReport', {status:selectedOption}, function(data) {
            console.log(data)
        });
    })
});