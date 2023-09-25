<?php
class LRSys {

    /**
     * @var string The name of the user or system.
     */
    public $name;
    
    /**
     * @var string The username used for authentication.
     */
    public $user;
    
    /**
     * @var string The password used for authentication.
     */
    private $pass;
    
    /**
     * @var string The email address of the user.
     */
    public $email;
    
    /**
     * @var bool Flag to determine whether to keep the session alive.
     */
    public $keepalive;
    
    /**
     * @var Session The session object for managing user sessions.
     */
    public $session;
    
    /**
     * @var string The language preference of the user or system.
     */
    private $lang;
    
    /**
     * @var PDO The PDO object for database interactions.
     */
    private $pdo;
    
    /**
     * @var mixed The process object or identifier.
     */
    private $process;
    
    /**
     * @var LogVPC The log object for logging activities or events.
     */
    private $log;
    
    /**
     * @var Ranking The ranking object for managing user rankings.
     */
    private $ranking;
    
    /**
     * @var Storyline The storyline object for managing the storyline or narrative.
     */
    private $storyline;
    
    /**
     * @var Clan The clan object for managing user clans or groups.
     */
    private $clan;
    
    /**
     * @var Mission The mission object for managing user missions or tasks.
     */
    private $mission;
    
    function __construct() {
        // Using an autoloader would allow for automatic loading of class files when needed,
        // reducing the need for manual require statements.
        // Example of using an autoloader:
        // spl_autoload_register(function ($class_name) {
        //     include $class_name . '.class.php';
        // });
    
        // Manually requiring necessary class files.
        require_once 'Session.class.php';
        require 'Player.class.php';
        require 'PC.class.php';
        require 'Ranking.class.php';
        require 'Storyline.class.php';
        require 'Clan.class.php';
    
        // Initializing the PDO object for database interactions.
        $this->pdo = PDO_DB::factory();
    
        // Initializing the session object for managing user sessions.
        $this->session = new Session();
    
        // Initializing various objects for managing logs, rankings, storylines, and clans.
        $this->log = new LogVPC();
        $this->ranking = new Ranking();
        $this->storyline = new Storyline();
        $this->clan = new Clan();
    
        // Setting the keepalive property to FALSE by default.
        $this->keepalive = FALSE;
    }

    public function set_keepalive($keep){
        // Validate the input parameter
        $this->keepalive = $keep;
    }

    public function register($username, $password, $email)
    {
        // Validate input parameters and consider using parameterized queries for SQL
        $this->user = $username;
        $this->pass = $password;
        $this->email = $email;
    
        require 'BCrypt.class.php';
        $bcrypt = new BCrypt();
        $hash = $bcrypt->hash(htmlentities($this->pass));
        // Consider using a more secure method for generating unique IPs
        $gameIP1 = rand(0, 255);
        $gameIP2 = rand(0, 255);
        $gameIP3 = rand(0, 255);
        $gameIP4 = rand(0, 255);
        $gameIP = $gameIP1 . '.' . $gameIP2 . '.' . $gameIP3 . '.' . $gameIP4;
        require 'Python.class.php';
        $python = new Python();
        $python->createUser($this->user, $hash, $this->email, $gameIP);
    
        // Use parameterized queries to prevent SQL injection
        $sql = 'SELECT COUNT(*) AS total, id FROM users WHERE login = :user LIMIT 1';
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute(array(':user' => $this->user));
        $regInfo = $stmt->fetch(PDO::FETCH_OBJ);
    
        if ($regInfo->total == 0) {
            $this->session->addMsg('Error while completing registration. Please, try again later.', 'error');
            return false;
        }
    
        require 'Finances.class.php';
        $finances = new Finances();
        $finances->createAccount($regInfo->id);
    
        // Use parameterized queries to prevent SQL injection
        $sql = "INSERT INTO stats_register (userID, ip) VALUES (:userID, :ip)";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute(array(':userID' => $regInfo->id, ':ip' => $_SERVER['REMOTE_ADDR']));
    
        $this->session->addMsg('Registration complete. You can login now.', 'notice');
    
        return $regInfo->id;
    }

    private function verifyRegister() {
        // Consider refactoring this method to reduce complexity and improve readability
        $system = new System();
        
        if(!$system->validate($this->user, 'username')){
            $this->session->addMsg(sprintf(_('Invalid username. Allowed characters are %s.'), '<strong>azAZ09._-</strong>'), 'error');
            return FALSE;
        }
        
        if(!$system->validate($this->email, 'email')){
            $this->session->addMsg(sprintf(_('The email %s is not valid.'), '<strong>'.$this->email.'</strong>'), 'error');
            return FALSE;
        }

        // Consider simplifying the email validation logic
        if ((strlen(preg_replace('![^A-Z]+!', '', $this->email)) >= 5 && preg_match_all("/[0-9]/", $this->email) >= 2) || preg_match_all("/[0-9]/", $this->email) >= 5){
            $this->session->addMsg(_('Registration complete. You can login now.'), 'notice');
            return FALSE;
        }

        if (strlen(preg_replace('![^A-Z]+!', '', $this->email)) >= 2 && strlen($this->email) <= 12){
            $this->session->addMsg(_('Registration complete. You can login now.'), 'notice');
            return FALSE;
        }
        
        $this->session->newQuery();
        // Use parameterized queries to prevent SQL injection
        $sqlQuery = "SELECT email FROM users WHERE login = ? OR email = ? LIMIT 1";
        $sqlLog = $this->pdo->prepare($sqlQuery);
        $sqlLog->execute(array($this->user, $this->email));

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
        
        if(strlen($this->user) > 15){
            $this->session->addMsg('Yor username is too big :( Please, limit it to 15 characteres.', 'error');
            return FALSE;
        }
        return TRUE;
    }

    public function getLastInsertedID()
    {
        // Consider adding a doc comment to explain the purpose of this method
        return $this->pdo->lastInsertId();
    }

    public function login($logUser, $logPass, $special = FALSE) {
        // Consider refactoring this method to reduce complexity and improve readability
        date_default_timezone_set('UTC');
        $remember = FALSE;
    
        if ($special) {
            if ($special == 'remember') {
                $remember = TRUE;
            } else {
                exit("Edit special");
            }
        }
    
        if (!$this->session) {
            $this->session = new Session();
        }
    
        require_once 'Mission.class.php';
        $this->mission = new Mission();
        $this->user = $logUser;
        $this->pass = $logPass;
    
        if ($this->verifyLogin(FALSE, $remember, FALSE)) {
            require 'BCrypt.class.php';
            $bcrypt = new BCrypt();
            $this->session->newQuery();
            // Use parameterized queries to prevent SQL injection
            $sqlQuery = "SELECT password, id FROM users WHERE BINARY login = ? LIMIT 1";
            $sqlLog = $this->pdo->prepare($sqlQuery);
            $sqlLog->execute(array($this->user));
    
            if ($sqlLog->rowCount() == '1') {
                $dados = $sqlLog->fetchAll();
    
                if ($bcrypt->verify($this->pass, $dados['0']['password']) || $remember) {
                    $log = $this->log;
                    $ranking = $this->ranking;
                    $storyline = $this->storyline;
                    $clan = $this->clan;
    
                    // Use parameterized queries to prevent SQL injection
                    $sql = "SELECT COUNT(*) AS total FROM users_premium WHERE id = ".$dados['0']['id']." LIMIT 1";
                    $total = $this->pdo->query($sql)->fetch(PDO::FETCH_OBJ)->total;
    
                    if ($total == 1) {
                        $premium = 1;
                    } else {
                        $premium = 0;
                    }
    
                    $this->session->loginSession($dados['0']['id'], $this->user, $premium, $special);
                    self::loginDatabase($dados['0']['id']);
                    $certsArray = $ranking->cert_getAll();
                    $this->mission->restoreMissionSession($dados['0']['id']);
                    $this->session->certSession($certsArray);
    
                    if ($clan->playerHaveClan($dados['0']['id'])) {
                        $_SESSION['CLAN_ID'] = $clan->getPlayerClan($dados['0']['id']);
                    } else {
                        $_SESSION['CLAN_ID'] = 0;
                    }
    
                    $_SESSION['LAST_CHECK'] = new DateTime('now');
                    $_SESSION['ROUND_STATUS'] = $storyline->round_status();
    
                    if ($_SESSION['ROUND_STATUS'] == 1) {
                        $log->addLog($dados['0']['id'], $log->logText('LOGIN', Array(0)), '0');
                        $this->session->exp_add('LOGIN');
                    }
    
                    return TRUE;
                } else {
                    $this->session->addMsg('Username and password doesn\'t match. Try again!', 'error');
                    return FALSE;
                }
            } else {
                $this->session->addMsg('Username and password doesn\'t match. Try again!', 'error');
                return FALSE;
            }
        }
    }    
    
    private function loginDatabase($id){
        // Consider adding a doc comment to explain the purpose of this method
        $this->session->newQuery();
        // Use parameterized queries to prevent SQL injection
        $sql = 'SELECT COUNT(*) AS total FROM users_online WHERE id = '.$id.' LIMIT 1';
        if($this->pdo->query($sql)->fetch(PDO::FETCH_OBJ)->total > 0){
            $this->session->newQuery();
            // Use parameterized queries to prevent SQL injection
            $sql = 'DELETE FROM users_online WHERE id = '.$id.' LIMIT 1';
            $this->pdo->query($sql);
        }
        require_once 'RememberMe.class.php';
        $key = pack("H*", '70617373776F7264243132333135313534');
        $rememberMe = new RememberMe($key, $this->pdo);
        $rememberMe->remember($id, false, $this->keepalive);
        $this->session->newQuery();
        // Use parameterized queries to prevent SQL injection
        $sql = 'UPDATE users SET lastLogin = NOW() WHERE id = :id';
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute(array(':id' => $id));
        setcookie('logged', '1', time() + 172800);
    }
    
    private function verifyLogin($fb, $tt, $rm) {
        // Consider adding a doc comment to explain the purpose of this method
        if($fb || $rm || $tt){
            return TRUE;
        }
        if (strlen($this->user) == '0' || strlen($this->pass) == '0') {
            $this->session->addMsg('Some fields are empty.', 'error');
            return FALSE;
        } else {
            return TRUE;
        }
    }
}

?>
