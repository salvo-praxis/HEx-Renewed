<?php

/**
 * SUMMARY:
 * 
 * The script facilitates launching a DDoS attack on a specified IP address, given 
 * certain prerequisites are satisfied. The script can be visualized as a sequence 
 * of interconnected blocks, each serving a distinct purpose in the overall workflow:
 * 
 * 1. **Session Initialization**:
 *    - Establishes a user session.
 *    - Redirects to the index page if the user is not logged in.
 * 
 * 2. **Request Validation**:
 *    - Checks if the request is of type POST.
 *    - Validates the presence of the 'ip' parameter in the request.
 *    - Sets an error message for any validation failure.
 * 
 * 3. **IP Address Validation**:
 *    - Uses the System class to validate the format of the provided IP address.
 *    - Sets an error message if the IP address is invalid.
 * 
 * 4. **Process Initiation**:
 *    - Initializes necessary classes for launching the attack.
 *    - Retrieves player information based on the IP address.
 *    - Validates the following conditions:
 *        a) The IP exists.
 *        b) The IP is listed in the user's Hacked Database.
 *        c) The user possesses at least 3 working DDoS viruses.
 *    - If all conditions are satisfied, initiates the DDoS attack process.
 *    - Adds a notice to the session indicating the launch of the attack.
 * 
 * 5. **Handle Errors**:
 *    - Any error encountered in the previous blocks is added to the session.
 *    - Provides a mechanism for debugging and user feedback.
 * 
 * 6. **Redirection**:
 *    - Independently of the success or failure of the previous blocks, the script 
 *      concludes by redirecting the user to a specific location.
 * 
 * Dependencies:
 * - Session.class.php: Manages user sessions.
 * - System.class.php: Provides IP address validation.
 * - Player.class.php: Retrieves player information by IP address.
 * - PC.class.php: Assumed to contain the Virus class. (UNDETERMINED)
 * - List.class.php: Checks whether the IP is listed in the Hacked Database.
 * 
 */

// ----------------------------------------
// BLOCK 1: SESSION INITIALIZATION
// ----------------------------------------
require 'classes/Session.class.php'; 
$session = new Session(); // Initialize session.

// Check if the user is logged in.
if (!$session->issetLogin()) {
    header("Location:index");
    exit();
}

// ----------------------------------------
// BLOCK 2: REQUEST VALIDATION
// ----------------------------------------
$error = ''; // Initialize error variable.

// Validate the request method.
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    $error = 'Invalid request type.';
}

// Validate IP address presence.
if (empty($error) && empty($_POST['ip'])) {
    $error = 'Invalid IP address.';
}

// ----------------------------------------
// BLOCK 3: IP ADDRESS VALIDATION
// ----------------------------------------
if (empty($error)) {
    require 'classes/System.class.php'; 
    $system = new System(); // Instantiate System class for IP validation.

    // Validate the provided IP.
    if (!$system->validate($_POST['ip'], 'ip')) {
        $error = 'Invalid IP address.';
    }
}

// ----------------------------------------
// BLOCK 4: PROCESS INITIATION
// ----------------------------------------
if (empty($error)) {
    // Include the necessary classes for Player, Virus, and List functionalities.
    require 'classes/Player.class.php';
    require 'classes/PC.class.php'; // Assumed to contain the Virus class.
    require 'classes/List.class.php';

    // Instantiate the classes.
    $virus = new Virus(); // Object for handling virus-related functionalities.
    $player = new Player(); // Object for handling player-related functionalities.
    $list = new Lists(); // Object for handling list-related functionalities.

    // Convert the IP address from a string to a long integer.
    $ip = ip2long($_POST['ip']);

    // Retrieve information about the player associated with the given IP address.
    $playerInfo = $player->getIDByIP($ip, '');

    // Check the conditions to initiate the process:
    // 1. The player exists.
    // 2. The IP is listed in the user’s Hacked Database.
    // 3. The user has at least 3 working DDoS viruses.
   if ($playerInfo['0']['existe'] !== 1) {
        $error = 'This IP doesnt exist.';
    } elseif (!$list->isListed($_SESSION['id'], $ip)) {
        $error = 'This IP is not on your Hacked Database.';
    } elseif ($virus->DDoS_count() < 3) {
        $error = 'You need to have at least 3 working DDoS viruses.';
   }
    
   if (empty($error)) 
   {
       // Instantiate the Process class for handling process-related functionalities.
        $process = new Process();

        // Determine whether the player is an NPC.
        // If 'pctype' is 'VPC', it is not an NPC (isNPC = 0), otherwise, it is an NPC (isNPC = 1).
        $isNPC = $playerInfo['0']['pctype'] === 'VPC' ? 0 : 1;

        // Try to initiate a new process.
        // If successful, add a notice message to the session.
        if ($process->newProcess(
                $_SESSION['id'], 
                'DDOS', 
                $playerInfo['0']['id'], 
                'remote', 
                '', 
                '', 
                '', 
                $isNPC)) {

            // Add a notice message to the session indicating that the DDoS attack was launched.
            $session->addMsg(
                sprintf(_('DDoS attack against <strong>%s</strong> launched.'), $_POST['ip']), 
                'notice'
            );
        }
    }
}

// ----------------------------------------
// BLOCK 5: HANDLE ERRORS
// ----------------------------------------
if (!empty($error)) {
    $session->addMsg($error, 'error');
}

// ----------------------------------------
// BLOCK 6: REDIRECTION
// ----------------------------------------
header("Location:list?action=ddos");
exit();
