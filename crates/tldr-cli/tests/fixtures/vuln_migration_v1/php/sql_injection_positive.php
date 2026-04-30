<?php
function handler($conn) {
    $id = $_GET["id"];
    mysqli_query($conn, "SELECT * FROM u WHERE id = " . $id);
}
