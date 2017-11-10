<?php
require_once 'include/DB_Functions.php';
$db = new DB_Functions();
 
// json response array
$response = array("error" => FALSE);
 
$post_body = file_get_contents('php://input');
$post_json = json_decode($post_body, true);

if (isset($post_json['email']) && isset($post_json['password'])) {
 
    // receiving the post params
    $email = $post_json['email'];
    $password = $post_json['password'];
 
    // get the user by email and password
    $user = $db->getUserByEmailAndPassword($email, $password);
 
    if ($user != false) {
        // use is found
        $response["error"] = FALSE;
        $response["id"] = $user[2];
	$response["role_id"] = $user[3];
        $response["user"]["name"] = $user[0];
        $response["user"]["email"] = $user[1];
        echo json_encode($response);
    } else {
        // user is not found with the credentials
        $response["error"] = TRUE;
        $response["error_msg"] = "Login credentials are wrong. Please try again!";
        echo json_encode($response);
    }
} else {
    // required post params is missing
    $response["error"] = TRUE;
    $response["error_msg"] = "Required parameters email or password is missing!";
    echo json_encode($response);
}
?>