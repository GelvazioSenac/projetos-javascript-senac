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
class ControllerApiProduto extends ControllerApiBase {

    public function index(Request $request, Response $response, array $args) {
        $sSql = "SELECT cd_prod
                        ,ds_prod
                        ,cd_grupo
                        ,cd_sub_grupo
                        ,fg_ativo
                        ,cd_cor
                        ,cd_fabrica
                        ,cd_marca
                        ,dt_alt
                        ,hr_alt
                        ,dt_cad
                        ,hr_cad
                        ,cd_gp_fiscal  
                        ,cd_ncm_sh
                        ,cd_ref 
                        ,cd_usuario
                        ,cd_filial
                        ,cd_unidade_medida
                        ,qt_estoque
                        ,tx_ipi
                        ,tx_iss 
                   FROM produto_simples ORDER BY 1 desc";
        $aDados = $this->getQuery()->selectAll($sSql);
        $xDados = array();
        foreach ($aDados as $sDados){
            array_push($xDados, $sDados);
        }

        $total = $this->getQuery()->select("select count(*) as total from produto_simples");
        $total = intval($total["total"]);
        
        $xDados = array(
            "success" => true,
            "total" => $total,
            "produtos" => $xDados
        );
        return $response->withJson($xDados, 200);
    }

    public function getProduto(Request $request, Response $response, array $args) {
        $sSql = "SELECT * FROM produto_simples ORDER BY cd_prod";
        $aDados = $this->getQuery()->selectAll($sSql);
        return $response->withJson($aDados, 200);
    }

    public function getConsultaProduto(Request $request, Response $response, array $args) {
        $sSql = "SELECT * FROM produto ORDER BY procodigo";
        $aDados = $this->getQuery()->selectAll($sSql);
        return $response->withJson($aDados, 200);
    }
}