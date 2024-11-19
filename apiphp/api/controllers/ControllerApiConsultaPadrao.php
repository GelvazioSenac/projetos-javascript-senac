<?php
use \Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Message\ResponseInterface as Response;

/**
 * Chamada da api Produto
 *
 * User: Gelvazio Camargo
 * Date: 10/12/2020
 * Time: 17:40
 */
require_once("ControllerApiBase.php");
class ControllerApiConsultaPadrao extends ControllerApiBase {

    public function getConsultaPadrao(Request $request, Response $response, array $args) {
    	$aDados = array("message" => "Erro ao buscar menu da consulta!");
    	$status = 400;
        
        $siscodigo = intval($args['siscodigo']);
        $mencodigo = intval($args['mencodigo']);
        if($mencodigo > 0 && $mencodigo > 0){
            $sSql = "SELECT mentabela FROM menu where siscodigo = $siscodigo and mencodigo = $mencodigo ORDER BY siscodigo, mencodigo";
            $aDados = $this->getQuery()->select($sSql);

            $tabela = $aDados["mentabela"];
            if($tabela == null){
                return $response->withJson(array("message" => "Tabela ou sistema não existe!"), $status);
            }

            // Retorna todos os registros da tabela passada por parametro
            $sSql = "SELECT * FROM $tabela ORDER BY 1";
            $aDados = $this->getQuery()->selectAll($sSql);
        	$status = 200;
        }

        
        return $response->withJson($aDados, $status);
    }
}