$('body').on('change', '#select_cipher_type', function() {
    if (!$(this).val()) {
        $('#private_key').fadeOut('fast').find('input').attr('disabled', true);
        $('#public_key').fadeOut('fast').find('input').attr('disabled', true);
        $('#save_button').fadeOut('fast').find('input').attr('disabled', true);
        return
    }
    if ($(this).val() == 1) {
        $('#public_key').fadeOut('fast').find('input').attr('disabled', true)
        $('#private_key').fadeIn('fast').find('input').attr('disabled', false);
    }
    if ($(this).val() == 2) {
        $('#public_key').fadeIn('fast').find('input').attr('disabled', false);
        $('#private_key').fadeIn('fast').find('input').attr('disabled', false);
    }
    $('#save_button').attr('disabled', false).fadeIn('fast');
});

$('body').on('click', '#show_object_properties', function () {
    $('#object_properties').fadeIn('fast');
    $(this).parent().hide();
});

$('body').on('click', '#hide_object_properties',function () {
    $('#object_properties').hide();
    $('#show_object_properties').parent().show();
});

$('body').on('change', '#select_object',function () {
    var object_id = $(this).val();
    window.location.replace('/'+object_id)
});

$('body').on('change', '#select_type',function () {
    value = $(this).val();
    $('.object-type').hide();
    $('.object-type#'+value).fadeIn('fast');
});

$('body').on('click', '#generate_keys',function (e) {
    e.preventDefault();
    var form = $(this).closest('form');
    generate_keys(form);
});
$('body').on('change', '#id_key_length',function (e) {
    e.preventDefault();
    var form = $(this).closest('form');
    generate_keys(form);
});

function generate_keys(form)
{
    var cipher_key_length_relation_id = form.find('#id_key_length').val();
    $.ajax({
        type: 'GET',
        url: '/generate_keys/',
        data: {'cipher_key_length_relation_id': cipher_key_length_relation_id},
        success: function(response) {
            var keys = response['data'];
            form.find('#id_private_key').html(keys[0]);
            form.find('#id_public_key').html(keys[1]);
        },
        error: function(data) {
            alert("There's been an error performing the request.")
        }

    });
}

$('body').on('change', "#id_cipher",function (e) {
    e.preventDefault();
    var form = $(this).closest('form');
    var cipher_id = $(this).val();
    form.find('#id_key_length').attr('disabled', true);
    $.ajax({
        type: 'GET',
        url: '/cipher_defaults/',
        data: {'cipher_id': cipher_id},
        success: function(response) {
            form.find('#key_length_field').html(response['key_length']);
            form.find('#private_key_field').html(response['private_key']);
            form.find('#public_key_field').html(response['public_key']);
            form.find('#fingerprint').html(response['fingerprint']);
        },
        error: function(data) {
            alert("There's been an error performing the request.")
        },
        complete: function() {
            form.find('#id_key_length').attr('disabled', false);
        }

    });
});


$('body').on('click', '#get_user_info', function() {
    $(this).attr('enabled', true);
    var user_block = $(this).parent();
    $.ajax({
        type: "GET",
        url: "/get_user_info/",
        success: function(response) {
            user_block.html(response);
        }

    });
})