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
class ControllerApiMenu extends ControllerApiBase {

    public function getMenu(Request $request, Response $response, array $args) {
        $sSql = "SELECT * FROM menu ORDER BY siscodigo, mencodigo";
        $siscodigo = intval($args['siscodigo']);
        if($siscodigo > 0){
            $sSql = "SELECT * FROM menu where siscodigo = $siscodigo ORDER BY siscodigo, mencodigo";
        }

        $aDados = $this->getQuery()->selectAll($sSql);
        return $response->withJson($aDados, 200);
    }
    
    public function getAllMenu(Request $request, Response $response, array $args) {
        //$sSql = "SELECT * FROM menu where mencodigo < 2 ORDER BY siscodigo, mencodigo";
        $sSql = "SELECT * FROM menu where mencodigo > 2 ORDER BY siscodigo, mencodigo";
//        $aDados = $this->getQuery()->selectAll($sSql);
//        return $response->withJson($aDados, 200);

        $aDados = $this->getQuery()->selectAllArray($sSql);
        $xDados = array();
        foreach ($aDados as $sDados){
            $dados = array();
            $dados[0] = $sDados[0];
            $dados[1] = 71;
            $dados[2] = 0.1;
            $dados[3] = 0.21;
            $dados[4] = '9/1 12:00am';
            array_push($xDados, $dados);
        }
        return $response->withJson($xDados, 200);
    }
}