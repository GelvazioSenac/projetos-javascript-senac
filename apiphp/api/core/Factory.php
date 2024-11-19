<?php

class Factory {
    /* Carrega os arquivos */

    public static function loadStaticModel($sModulo, $sClasse) {
        $oModel = strtolower($sModulo) . '_class_model_' . strtolower($sClasse) . '.php';
        $oModelClasse = new $oModel;
        return $oModelClasse;
    }

    public static function loadStaticController($sModulo, $sClasse) {
        $oModel = strtolower($sModulo) . '_class_controller_' . strtolower($sClasse) . '.php';
        $oModelClasse = new $oModel;
        return $oModelClasse;
    }

    public static function loadPersistencia($sClasse) {
        $oClasse = 'Persistencia' . $sClasse;
        $oClasse = new $oClasse;
        return $oClasse;
    }

    public static function loadController($sClasse) {
        $oClasse = 'Controller' . $sClasse;
        $oClasse = new $oClasse;
        return $oClasse;
    }

    public static function loadView($sClasse) {
        $oClasse = 'View' . $sClasse;
        $oClasse = new $oClasse;
        return $oClasse;
    }

    public static function loadModel($sClasse) {
        $oClasse = 'Model' . $sClasse;
        $oClasse = new $oClasse;
        return $oClasse;
    }

}