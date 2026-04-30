<?php
function handler($conn) {
    $name = $_GET["name"];
    echo "<h1>" . $name . "</h1>";
}
