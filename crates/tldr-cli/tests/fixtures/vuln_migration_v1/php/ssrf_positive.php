<?php
function handler($conn) {
    $u = $_GET["u"];
    file_get_contents($u);
}
