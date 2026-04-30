<?php
// vt=CommandInjection lang=php — names below are inside strings/comments only
// $_GET is a source. mysqli_query, echo, shell_exec, fopen,
// file_get_contents, unserialize are sinks. Referenced in strings only below.

function docs() {
    $doc = '$_GET[id] flows into mysqli_query(SELECT ... )';
    $more = 'shell_exec, fopen, file_get_contents, unserialize, echo — string-only';
    return $doc . $more;
}
