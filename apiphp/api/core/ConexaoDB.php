<?php

class ConexaoDB {

    private static  $HOST = 'aws-0-sa-east-1.pooler.supabase.com';
    private static  $PORT = '5432';
    private static  $DBNAME = 'postgres';
    private static  $USER = 'postgres.vtglfccczgitidfkllmq';
    private static  $PASS = 'rSttFjHYykMs2X8G';


    private static $conexao = null;

    public static function getInstance() {
        if (is_null(self::$conexao)) {
            self::conecta();
        }
        return self::$conexao;
    }

    private static function loadVariaveis() {
        $env = file_get_contents(__DIR__ . "/variaveis.json");

        $env = json_decode($env, true);

        putenv("HOST=" . $env["HOST"]);
        putenv("PORT=" . $env["PORT"]);
        putenv("DBNAME=" . $env["DBNAME"]);
        putenv("USER=" . $env["USER"]);
        putenv("PASS=" . $env["PASS"]);
    }

    public static function conecta() {
        if (is_null(self::$conexao)) {
            self::loadVariaveis();

            self::$HOST = getenv("HOST");
            self::$PORT = getenv("PORT");
            self::$DBNAME = getenv("DBNAME");
            self::$USER = getenv("USER");
            self::$PASS = getenv("PASS");

            $link = 'host=' . self::$HOST . ' port=' . self::$PORT . ' dbname=' . self::$DBNAME . ' user=' . self::$USER . ' password=' . self::$PASS;
            self::$conexao = pg_connect($link);
            if (self::$conexao === false) {
                throw new Exception('Erro ao comunicar com banco de dados!');
            }
        }
        return self::$conexao;
    }

    public static function desconecta() {
        $bFechou = true;
        if (!is_null(self::$conexao)) {
            $bFechou = pg_close(self::$conexao);
            self::$conexao = null;
        }
        return $bFechou;
    }

    public function __destruct() {
        self::desconecta();
    }

}