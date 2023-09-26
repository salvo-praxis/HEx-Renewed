<?php
/**
 * Class LRSys
 * 
 * This class handles various system-level functionalities such as user registration,
 * login, session management, and interactions with other classes.
 */
class LRSys {

    // Declare class properties
    /**
     * @var string $name
     * Holds the name of the user or system component.
     */
    public $name;

    /**
     * @var string $user
     * Holds the username of the user interacting with the system.
     */
    public $user;

    /**
     * @var string $pass
     * Holds the password of the user. Kept private for security reasons.
     */
    private $pass;

    /**
     * @var string $email
     * Holds the email address of the user.
     */
    public $email;

    /**
     * @var bool $keepalive
     * Flag to determine whether the session should be kept alive.
     */
    public $keepalive;

    /**
     * @var Session $session
     * Holds the session object for managing user sessions.
     */
    public $session;

    /**
     * @var string $lang
     * Holds the preferred language of the user.
     */
    private $lang;

    /**
     * @var PDO $pdo
     * Holds the PDO object for database interactions.
     */
    private $pdo;

    /**
     * @var string $process
     * Holds the current process or action being performed in the system.
     */
    private $process;

    /**
     * @var LogVPC $log
     * Holds the LogVPC object for logging system events.
     */
    private $log;

    /**
     * @var Ranking $ranking
     * Holds the Ranking object for managing user rankings.
     */
    private $ranking;

    /**
     * @var Storyline $storyline
     * Holds the Storyline object for managing the game's storyline.
     */
    private $storyline;

    /**
     * @var Clan $clan
     * Holds the Clan object for managing user clans.
     */
    private $clan;

    /**
     * @var Mission $mission
     * Holds the Mission object for managing user missions.
     */
    private $mission;
    
    
    /**
     * Constructor
     * 
     * Initializes the LRSys class and its dependencies.
     */
    function __construct() {
        // Include required class files
        require_once 'Session.class.php';
        $this->pdo = PDO_DB::factory();
        $this->session = new Session();
        require 'Player.class.php';
        require 'PC.class.php';
        require 'Ranking.class.php';
        require 'Storyline.class.php';
        require 'Clan.class.php';

        // Initialize log, ranking, storyline, and clan objects
        $this->log = new LogVPC();
        $this->ranking = new Ranking();
        $this->storyline = new Storyline();
        $this->clan = new Clan();

        // Set the keepalive property to FALSE by default
        $this->keepalive = FALSE;
    }

    // Method to set the keepalive property
    public function set_keepalive($keep){
        $this->keepalive = $keep;
    }

    /**
     * Register
     * 
     * Registers a new user in the system.
     * 
     * @param string $username The username of the new user.
     * @param string $password The password of the new user.
     * @param string $email The email address of the new user.
     * @return int|bool The ID of the newly registered user, or false on failure.
     */
    public function register($username, $password, $email) {
        // Set user, pass, and email properties
        $this->user = $username;
        $this->pass = $password;
        $this->email = $email;
    
        // Include BCrypt class and create a new BCrypt object
        require 'BCrypt.class.php';
        $bcrypt = new BCrypt();
        // Hash the password using BCrypt
        $hash = $bcrypt->hash(htmlentities($this->pass));
        // Generate a random game IP address
        $gameIP1 = rand(0, 255);
        $gameIP2 = rand(0, 255);
        $gameIP3 = rand(0, 255);
        $gameIP4 = rand(0, 255);
        $gameIP = $gameIP1 . '.' . $gameIP2 . '.' . $gameIP3 . '.' . $gameIP4;
        // Include Python class and create a new Python object
        require 'Python.class.php';
        $python = new Python();
        // Call the createUser method of the Python object
        $python->createUser($this->user, $hash, $this->email, $gameIP);
    
        // SQL query to select the user from the users table
        $sql = 'SELECT COUNT(*) AS total, id FROM users WHERE login = :user LIMIT 1';
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute(array(':user' => $this->user));
        $regInfo = $stmt->fetch(PDO::FETCH_OBJ);
    
        // Check if the user registration is successful
        if ($regInfo->total == 0) {
            $this->session->addMsg('Error while completing registration. Please, try again later.', 'error');
            return false;
        }
    
        // Include Finances class and create a new Finances object
        require 'Finances.class.php';
        $finances = new Finances();
        // Call the createAccount method of the Finances object
        $finances->createAccount($regInfo->id);
    
        // SQL query to insert the user into the stats_register table
        $sql = "INSERT INTO stats_register (userID, ip) VALUES (:userID, :ip)";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute(array(':userID' => $regInfo->id, ':ip' => $_SERVER['REMOTE_ADDR']));
    
        // Add a notice message to the session
        $this->session->addMsg('Registration complete. You can login now.', 'notice');
    
        // Return the user ID
        return $regInfo->id;
    }

    /**
     * Verify Register
     * 
     * Verifies the registration details provided by the user.
     * 
     * @return bool True if the registration details are valid, false otherwise.
     */
    private function verifyRegister() {
        // Create a new System object
        $system = new System();
        
        // Validate the username and email
        if(!$system->validate($this->user, 'username')){
            $this->session->addMsg(sprintf(_('Invalid username. Allowed characters are %s.'), '<strong>azAZ09._-</strong>'), 'error');
            return FALSE;
        }
        
        if(!$system->validate($this->email, 'email')){
            $this->session->addMsg(sprintf(_('The email %s is not valid.'), '<strong>'.$this->email.'</strong>'), 'error');
            return FALSE;
        }

        // Additional email validation checks
        if ((strlen(preg_replace('![^A-Z]+!', '', $this->email)) >= 5 && preg_match_all("/[0-9]/", $this->email) >= 2) || preg_match_all("/[0-9]/", $this->email) >= 5){
            $this->session->addMsg(_('Registration complete. You can login now.'), 'notice');
            return FALSE;
        }

        if (strlen(preg_replace('![^A-Z]+!', '', $this->email)) >= 2 && strlen($this->email) <= 12){
            $this->session->addMsg(_('Registration complete. You can login now.'), 'notice');
            return FALSE;
        }
        
        // SQL query to select the user from the users table by username or email
        $this->session->newQuery();
        $sqlQuery = "SELECT email FROM users WHERE login = ? OR email = ? LIMIT 1";
        $sqlLog = $this->pdo->prepare($sqlQuery);
        $sqlLog->execute(array($this->user, $this->email));

        // Check if the username or email is already taken
        if ($sqlLog->rowCount() == '1') {
            $dados = $sqlLog->fetch();
            if ($dados['email'] == $this->email) {
                $this->session->addMsg('This email is already used.', 'error');
            } else {
                $this->session->addMsg('This username is already taken.', 'error');
            }
            return FALSE;             
        } elseif (strlen($this->user) == '0' || strlen($this->pass) == '0' || strlen($this->email) == '0') {
            $this->session->addMsg('Some fields are empty.', 'error');
            return FALSE;
        }
        
        // Check if the username length is within the limit
        if(strlen($this->user) > 15){
            $this->session->addMsg('Your username is too big :( Please, limit it to 15 characters.', 'error');
            return FALSE;
        }
        return TRUE;
    }

    /**
     * Get Last Inserted ID
     * 
     * Retrieves the ID of the last inserted record in the database.
     * 
     * @return int The last inserted ID.
     */
    public function getLastInsertedID() {
        return $this->pdo->lastInsertId();
    }

    /**
     * Login
     * 
     * Logs in a user to the system.
     * 
     * @param string $logUser The username of the user.
     * @param string $logPass The password of the user.
     * @param bool $special Special login flag.
     * @return bool True on successful login, false otherwise.
     */
    public function login($logUser, $logPass, $special = FALSE) {
        // Set the timezone to UTC
        date_default_timezone_set('UTC');
        $remember = FALSE;
    
        // Check if the special parameter is set to 'remember'
        if ($special) {
            if ($special == 'remember') {
                $remember = TRUE;
            } else {
                exit("Edit special");
            }
        }
    
        // Check if the session object is initialized
        if (!$this->session) {
            $this->session = new Session();
        }
    
        // Include Mission class and create a new Mission object
        require_once 'Mission.class.php';
        $this->mission = new Mission();
        // Set user and pass properties
        $this->user = $logUser;
        $this->pass = $logPass;
    
        // Verify the login credentials
        if ($this->verifyLogin(FALSE, $remember, FALSE)) {
            // Include BCrypt class and create a new BCrypt object
            require 'BCrypt.class.php';
            $bcrypt = new BCrypt();
            $this->session->newQuery();
            // SQL query to select the user from the users table by username
            $sqlQuery = "SELECT password, id FROM users WHERE BINARY login = ? LIMIT 1";
            $sqlLog = $this->pdo->prepare($sqlQuery);
            $sqlLog->execute(array($this->user));
    
            // Check if the user exists in the database
            if ($sqlLog->rowCount() == '1') {
                $dados = $sqlLog->fetchAll();
    
                // Verify the password using BCrypt
                if ($bcrypt->verify($this->pass, $dados['0']['password']) || $remember) {
                    // Initialize log, ranking, storyline, and clan objects
                    $log = $this->log;
                    $ranking = $this->ranking;
                    $storyline = $this->storyline;
                    $clan = $this->clan;
    
                    // SQL query to check if the user has a premium account
                    $sql = "SELECT COUNT(*) AS total FROM users_premium WHERE id = ".$dados['0']['id']." LIMIT 1";
                    $total = $this->pdo->query($sql)->fetch(PDO::FETCH_OBJ)->total;
    
                    // Set the premium variable based on the query result
                    if ($total == 1) {
                        $premium = 1;
                    } else {
                        $premium = 0;
                    }
    
                    // Call the loginSession method of the session object
                    $this->session->loginSession($dados['0']['id'], $this->user, $premium, $special);
                    // Call the loginDatabase method
                    self::loginDatabase($dados['0']['id']);
                    // Get all certificates and restore mission session
                    $certsArray = $ranking->cert_getAll();
                    $this->mission->restoreMissionSession($dados['0']['id']);
                    // Set the certificate session
                    $this->session->certSession($certsArray);
    
                    // Check if the player has a clan and set the CLAN_ID session variable
                    if ($clan->playerHaveClan($dados['0']['id'])) {
                        $_SESSION['CLAN_ID'] = $clan->getPlayerClan($dados['0']['id']);
                    } else {
                        $_SESSION['CLAN_ID'] = 0;
                    }
    
                    // Set the LAST_CHECK and ROUND_STATUS session variables
                    $_SESSION['LAST_CHECK'] = new DateTime('now');
                    $_SESSION['ROUND_STATUS'] = $storyline->round_status();
    
                    // Check the round status and add login log and experience
                    if ($_SESSION['ROUND_STATUS'] == 1) {
                        $log->addLog($dados['0']['id'], $log->logText('LOGIN', Array(0)), '0');
                        $this->session->exp_add('LOGIN');
                    }
    
                    // Return TRUE to indicate successful login
                    return TRUE;
                } else {
                    // Add an error message to the session and return FALSE
                    $this->session->addMsg('Username and password don\'t match. Try again!', 'error');
                    return FALSE;
                }
            } else {
                // Add an error message to the session and return FALSE
                $this->session->addMsg('Username and password don\'t match. Try again!', 'error');
                return FALSE;
            }
        }
    }    
    
    /**
     * Login Database
     * 
     * Handles database interactions for user login.
     * 
     * @param int $id The ID of the user.
     */
    private function loginDatabase($id) {
        // SQL query to check if the user is online
        $this->session->newQuery();
        $sql = 'SELECT COUNT(*) AS total FROM users_online WHERE id = '.$id.' LIMIT 1';
        if($this->pdo->query($sql)->fetch(PDO::FETCH_OBJ)->total > 0){
            // SQL query to delete the user from the users_online table
            $this->session->newQuery();
            $sql = 'DELETE FROM users_online WHERE id = '.$id.' LIMIT 1';
            $this->pdo->query($sql);
        }
        // Include RememberMe class and create a new RememberMe object
        require_once 'RememberMe.class.php';
        $key = pack("H*", '70617373776F7264243132333135313534');
        $rememberMe = new RememberMe($key, $this->pdo);
        // Call the remember method of the RememberMe object
        $rememberMe->remember($id, false, $this->keepalive);
        // SQL query to update the lastLogin field of the users table
        $this->session->newQuery();
        $sql = 'UPDATE users SET lastLogin = NOW() WHERE id = :id';
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute(array(':id' => $id));
        // Set the logged cookie
        setcookie('logged', '1', time() + 172800);
    }
    
    /**
     * Verify Login
     * 
     * Verifies the login details provided by the user.
     * 
     * @param bool $fb Facebook login flag.
     * @param bool $tt Twitter login flag.
     * @param bool $rm Remember me flag.
     * @return bool True if the login details are valid, false otherwise.
     */
    private function verifyLogin($fb, $tt, $rm) {
        // Check if the login is through Facebook, Twitter, or Remember Me
        if($fb || $rm || $tt){
            return TRUE;
        }
        // Check if the username or password fields are empty
        if (strlen($this->user) == '0' || strlen($this->pass) == '0') {
            $this->session->addMsg('Some fields are empty.', 'error');
            return FALSE;
        } else {
            return TRUE;
        }
    }
}

?>
