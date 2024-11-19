<?php

/**
 * Arquivo com funções uteis
 * User: Gelvazio Camargo
 * Date: 22/09/2024
 * Time: 11:00
 */

require_once 'lib/phpfastcache/phpfastcache.php';

class Utils {

    public static function isServidorProducao() {
        return false;
    }

    public static function getCacheServer() {
        $serverCache = "redis";
        if ((key_exists("SERVERCACHE", $_SESSION)) && ($_SESSION["SERVERCACHE"] != "")) {
            $serverCache = $_SESSION["SERVERCACHE"];
        }

        if ((Utils::isServidorProducao()) && ($serverCache != "files")) {
            if (!isset($_SERVER["SERVER_REDIS"])) {
                // Ip da maquina local quando não estiver em nuvem
                $host = '192.168.1.2';
                $_SERVER["SERVER_REDIS"] = $host;
            }

            $cache = phpFastCache("predis", array(
                "redis" => array(
                    "host" => $_SERVER["SERVER_REDIS"],
                    "port" => 6379
                )
            ));

            return $cache;
        }

        $cache = phpFastCache("files");

        return $cache;
    }

    public static function getRemoteIP() {
        $remoteIP = $_SERVER['REMOTE_ADDR'];
        if (array_key_exists('HTTP_X_FORWARDED_FOR', $_SERVER)) {
            $remoteIP = $_SERVER["HTTP_X_FORWARDED_FOR"];
        } else if (array_key_exists('REMOTE_ADDR', $_SERVER)) {
            $remoteIP = $_SERVER["REMOTE_ADDR"];
        } else if (array_key_exists('HTTP_CLIENT_IP', $_SERVER)) {
            $remoteIP = $_SERVER["HTTP_CLIENT_IP"];
        }

        if (stristr($remoteIP, ",")) {
            $listaIps = explode(",", $remoteIP);

            $remoteIP = $listaIps[0];
        }

        return $remoteIP;
    }

    public static function enviaMensagemSlack($assunto, $message, $room = "geral") {
        try {
            $assunto = str_ireplace("<br>", "\n", $assunto);
            $assunto = str_ireplace("<br/>", "\n", $assunto);

            $message = str_ireplace("<br>", "\n", $message);
            $message = str_ireplace("<br/>", "\n", $message);

            $data = "payload=" . json_encode(array(
                    "channel" => "#{$room}",
                    "text" => "[$assunto] \n$message"
                ));

            // You can get your webhook endpoint from your Slack settings
            $url_app_gelvazio = "https://hooks.slack.com/services/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";
            if ($room == 'geral') {
                $url_app_gelvazio = "https://hooks.slack.com/services/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";
            }

            $ch = curl_init($url_app_gelvazio);
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

            $result = curl_exec($ch);

            curl_close($ch);

            return $result;
        } catch (Exception $ex) {

        }
    }

    public static function checkRateLimit($app, $tag) {
        // Implementar rate limits
        return true;

        // 50 Requisições por minuto
        if (!self::checkRateLimitRedis($app, $tag, 50, 60)) {
            return false;
        }

        // 500 Requisições por 10 minutos
        if (!self::checkRateLimitRedis($app, $tag, 500, 60 * 10)) {
            return false;
        }

        // 3000 Requisições por hora
        if (!self::checkRateLimitRedis($app, $tag, 3000, 60 * 60)) {
            return false;
        }

        // 30000 Requisições por 10 horas
        if (self::checkRateLimitRedis($app, $tag, 30000, 60 * 60 * 10)) {
            return false;
        }

        return true;
    }

    private static function checkRateLimitRedis($app, $key, $max, $time = 1) {
        if (trim($key) != "" && strlen(trim($key)) > 4) {
            $keyCache = "RATE_LIMIT_" . $app . "_" . $key . "_" . $max;

            $cache = Utils::getCacheServer();
            $object = $cache->get($keyCache, array('all_keys' => true));
            if ($object == null) {
                // quando nao existe, cria com o tempo certo
                $cache->set($keyCache, 0, $time);
            }

            // Feita implementacao aqui, pois estava acrescentando 5 anos, cada vez que expirava a primeira vez para cada chave
            $time_expired = $object['expired_time'] - @date("U");
            $count = intval($cache->get($keyCache));

            if ((Int)$time_expired <= 0) {
                $cache->set($keyCache, 0, $time);
            } else {
                $count = $count + 1;
                $cache->set($keyCache, $count, $time_expired);
            }

            if ($count > $max) {
                $assunto = "Rate limit [$app]";
                $texto = "Key: $key<br>Count: $count <br>Max: $max<br>Time: $time";

                Utils::enviaMensagemSlack($assunto, $texto, "geral");

                return false;
            }
        }
        return true;
    }

    public static function getConexao() {
        $IP = "";
        $DATABASE_NAME = "DATABASE_NAME";

        // Conecta no banco de dados
        $user = "USER";
        $password = "123456";

        // Conecta no banco de dados
        $conexaoBancoDados = pg_connect("host=$IP port=5432 dbname=$DATABASE_NAME user=$user password=$password");

        // Coloca o cliente enconding
        pg_set_client_encoding($conexaoBancoDados, "UTF-8");

        // Define o nome da aplicação
        $appName = "apiphpsenac";

        pg_query("SET application_name = '$appName';");

        // Retorna a conexao
        return $conexaoBancoDados;
    }

    /**
     * Gera token de autenticação
     * @param $usucodigo
     * @param $dadosAdicionais
     * @return string
     * @throws Exception
     */
    public static function encodeToken($usucodigo, $dadosAdicionais = false) {
        $jwtKey = "apiphp-" . date("Y-m-d") . "-key-jwt";

        $usucodigo = intval($usucodigo);
        $dados = array(
            "usucodigo" => $usucodigo,
            "dataToken" => date("Y-m-d"),
        );

        // Coloca os dados adicionais no token
        if (is_array($dadosAdicionais)) {
            $dados = array_merge($dados, $dadosAdicionais);
        }

        require_once '../lib/jwt/jwt_helper.php';

        return JWT::encode($dados, $jwtKey);
    }

    /**
     * Decodifica o token
     * @param $token
     * @return object
     */
    public static function decodeToken($token) {
        $jwtKey = "apiphp-" . date("Y-m-d") . "-key-jwt";

        require_once '../lib/jwt/jwt_helper.php';

        return JWT::decode($token, $jwtKey);
    }

}