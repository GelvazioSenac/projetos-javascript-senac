<?php
use \Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Message\ResponseInterface as Response;

/**
 * Contem os metodos base de chamada da api que são chamados em mais de uma rota.
 *
 * User: Gelvazio Camargo
 * Date: 10/12/2020
 * Time: 17:40
 */
require_once("./core/Query.php");
require_once("./core/HttpStatusCodes.php");
class ControllerApiBase {

    public function callInfoApi(Request $request, Response $response, array $args) {

        $data = array("Info:" => date("Y-m-d H:i:s"));

        return $response->withStatus(201)->withJson($data, 200);
    }

    public function callPing(Request $request, Response $response, array $args) {
        $sSql = "SELECT * FROM menu ORDER BY siscodigo, mencodigo";
        $siscodigo = intval($args['siscodigo']);
        if($siscodigo > 0){
            $sSql = "SELECT * FROM menu where siscodigo = $siscodigo ORDER BY siscodigo, mencodigo";
        }

        $aDados = $this->getQuery()->selectAll($sSql);
        return $response->withJson($aDados, 200);
    }

    /**
     *
     * @var ModelPadrao
     */
    protected $Model;

    /**
     *
     * @var Query
     */
    private $Query;

    public function getQuery() {
        if (!isset($this->Query)) {
            $this->Query = new Query();
        }
        return $this->Query;
    }

    public function setQuery(Query $Query) {
        $this->Query = $Query;
    }

    public function getModel() {
        return $this->Model;
    }

    public function setModel(ModelPadrao $Model) {
        $this->Model = $Model;
    }
}