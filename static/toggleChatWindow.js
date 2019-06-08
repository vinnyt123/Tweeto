$(document).ready(function(){
    var selectedUser = ""

    $(".onlineUser").click(function(){
        $(".sendMessageButton").prop('disabled', false);
        selectedUser = $(this).text();
        $(".personNameLabel").text(selectedUser);
        $(".loading").show();
        $.post('/getMessageHistory', {userName: selectedUser}, function(data) {
            $(".loading").hide();
            $(".chatArea").html(data);
        });
    });

    $(".sendMessageButton").click(function(){
        $(".chatArea").append("<div class='messageWrapper'><div class='sendingMessage'>" + $(".messageBox").val() + "</div></div>");
        $.post('/send_private_message', {username: selectedUser, message: $(".messageBox").val()}, function(data) {
            $(".sendingMessage").addClass("sentMessage");
            $(".sendingMessage").removeClass("sendingMessage");
        });
    });
});