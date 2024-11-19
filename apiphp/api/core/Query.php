<?php

require_once("ConexaoDB.php");
class Query {

    private $conexao;

    public function __construct() {
        $this->conexao = ConexaoDB::getInstance();
    }

    public function select($sSql) {
        $rSql = $this->query($sSql);
        if ($oLinhaAtual = pg_fetch_assoc($rSql)) {
            return $oLinhaAtual;
        }
        return false;
    }

    public function selectAll($sSql) {
        $rSql = $this->query($sSql);
        $aRetorno = Array();
        while ($oLinhaAtual = pg_fetch_assoc($rSql)) {
            $aRetorno[] = $oLinhaAtual;
        }
        return $aRetorno;
    }

    public function query($sSql) {
        $rRetorno = @pg_query($this->conexao, $sSql);
        if ($rRetorno !== false) {
            return $rRetorno;
        }

        // ENVIAR AO SENTRY AQUI!
        $mensagem = "SQL: $sSql <br>Erros:" . pg_last_error($this->conexao);
                
        Utils::enviaMensagemSlack('Erro na query!',$mensagem);

        throw new Exception('Erro ao executar comando SQL');
    }

}