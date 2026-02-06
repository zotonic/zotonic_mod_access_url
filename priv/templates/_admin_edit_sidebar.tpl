{% extends "admin_edit_widget_std.tpl" %}

{% block widget_title %}
{_ Share link to this page _}
<div class="widget-header-tools">
    <a href="#" class="z-btn-help do_dialog" data-dialog="{{
        %{
            title: _"Help about sharing links",
            text: _"Share a link to this page. Anyone with the link can access the page using your view permissions. The link is valid for the defined duration or indefinitely."
        }|escape
    }}" title="{_ Need more help? _}"></a>
</div>
{% endblock %}

{% block widget_show_minimized %}true{% endblock %}
{% block widget_id %}admin_share_link_sidebar{% endblock %}

{% block widget_content %}
    {% if id.is_visible %}
        <p class="help-block">{_ Share a link to this page. Anyone with the link can view the page and the images on it with your viewing permissions. They will not receive any additional update or edit permissions. _}</p>

        <div class="form-inline">
            <div class="form-group">
                <label>{_ Valid for _}</label>
                <select class="form-control nosubmit" id="{{ #validfor }}">
                    <option value="">{_ Forever _}</option>
                    <option value="+day">{_ Day _}</option>
                    <option value="+week">{_ Week _}</option>
                    <option value="+month">{_ Month _}</option>
                    <option value="+2 months">{_ Two months _}</option>
                    <option value="+3 months">{_ Three months _}</option>
                    <option value="+6 months">{_ Six months _}</option>
                    <option value="+year">{_ Year _}</option>
                </select>
            </div>
            <button class="btn btn-default" type="button" id="{{ #share }}">{_ Generate link _}</button>
            {% javascript %}
                $('#{{ #share }}').click(function() {
                    cotonic.broker.call(
                        "bridge/origin/model/access_url/get/generate",
                        {
                            "id": {{ id }},
                            "valid_for": $('#{{ #validfor }}').val()
                        }).then(
                            (msg) => {
                                const url = msg.payload.result;
                                $('#{{ #link }}').text(url);
                                $('#{{ #linkdiv }}').fadeIn();
                            }
                        )
                });
            {% endjavascript %}
        </div>

        <br>

        <div class="form-group" id="{{ #linkdiv }}" style="display: none">
            <tt style="font-size: small; display: block; overflow:hidden; white-space: nowrap; max-width: 100%; text-overflow: ellipsis; padding: 10px 0;" id="{{ #link }}"></tt>
            <p class="text-center">
                <button id="{{ #copy }}" type="button" class="btn btn-default btn-xs">
                    <span class="glyphicon glyphicon-copy"></span> {_ Copy to clipboard _}
                </button>
                {% javascript %}
                    $('#{{ #copy }}').click(function() {
                        const text = $('#{{ #link  }}').text();
                        if (text !== '' && navigator.clipboard) {
                            navigator.clipboard
                                .writeText(text)
                                .then(
                                    function() {
                                        $('#{{ #link  }}').effect('highlight', 1000);
                                        z_growl_add("{_ Copied to clipboard _}");
                                    },
                                    function(err) {
                                        console.error('Async: Could not copy text: ', err);
                                    });
                        }
                    });
                {% endjavascript %}
            </p>
        </div>

    {% else %}
        <p class="text-warning"><i class="fa fa-info-circle"></i> {_ You must be able to view the page to see it. _}</p>
    {% endif %}
{% endblock %}
