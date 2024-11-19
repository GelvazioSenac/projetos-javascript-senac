function validaSessaoSistema(pagina){
    const usuario_logado = sessionStorage.getItem("usuario_logado");
    const token_logado = sessionStorage.getItem("token_logado");
    
    const token_verificar = "54a80097f23822cb26b6d5a980968601" + usuario_logado;
    console.log("usuario_logado: " + usuario_logado);    
    console.log("token_logado  : " + token_logado);
    console.log("tokenverificar: " + token_verificar);
    
    
    // valida o token logado
    if (token_logado == "54a80097f23822cb26b6d5a980968601" + usuario_logado) { 
        console.log("SESSAO VALIDADA COM SUCESSO!");

        atualizaMenu();

        const email_usuario_logado = sessionStorage.getItem("email_usuario_logado");
        
        if(pagina == "PAGINA_DE_VENDAS"){
            document.querySelector("#email_usuario_logado").innerHTML = email_usuario_logado;       
        } else {
            document.querySelector("#email_usuario_logado").value = email_usuario_logado;       
        }
        
        return true;
    }

    window.location.href = "login.html";

    return false;    
}

function confirmarLogin(){
    const email = document.querySelector("#email").value;
    const senha = document.querySelector("#senha").value;

    const body = {
        email: email,
        senha: senha,
    };

    callApiPost(
        "POST",
        "usuarios",
        function (data) {
            // VALIDAR LOGIN
            validarLoginSistema(data, email, senha);
        },
        body
    );
}

function validarLoginSistema(aListaDados, email, senha){
    // Se não for array, coloca como array
    if (!Array.isArray(aListaDados)) {
        aListaDados = new Array(aListaDados);
    }

    let valida = false;
    let dadosUsuario = "";
    let email_usuario_logado = "";
    aListaDados.forEach(function (data, key) {
        // percorre os usuarios e valida a senha e email
        if(data.email == email && data.senha == senha){
            valida = true;
            dadosUsuario = data.id;
            email_usuario_logado = data.email;
        }
    });

    if(valida){
        // SETA O TOKEN
        sessionStorage.setItem(
            "token_logado",
            "54a80097f23822cb26b6d5a980968601" + dadosUsuario
        );

        // SETA O USUARIO LOGADO
        sessionStorage.setItem("usuario_logado", dadosUsuario);
        sessionStorage.setItem("email_usuario_logado", email_usuario_logado);
        
        // REDIRECIONA PARA A HOME
        window.location.href = "produtos.html";
    } else {
        alert("Usuário ou senha não conferem!")
    }
}

function cadastrarLogin(){
    alert("Implementar...");
}

function logout(){
    sessionStorage.removeItem(
        "token_logado"        
    );

    sessionStorage.removeItem(
        "usuario_logado"        
    );

    window.location.href = "produtos.html";
}

function atualizaMenu() {
    var url_atual = window.location.href;
    // let baseUrl = "https://b2system.vercel.app/";
    let baseUrl = "https://b2systemsenac.vercel.app/";
    if (url_atual.includes("http://127.0.0.1:5500/")) {
        baseUrl = "http://127.0.0.1:5500/";
    }

    const menu = ` <li id="aba-index">
                        <a href="index.html">
                            <i class='bx bx-grid-alt'></i>
                            <span class="links_name">Principal</span>
                        </a>
                    </li>
                    <li id="aba-produtos">
                        <a href="${baseUrl}produtos.html">
                            <i class='bx bx-box'></i>
                            <span class="links_name">Produtos</span>
                        </a>
                    </li>
                    <li id="aba-clientes">
                        <a href="${baseUrl}clientes.html">
                            <i class='bx bx-list-ul'></i>
                            <span class="links_name">Clientes</span>
                        </a>
                    </li>
                    <li id="aba-vendas">
                        <a href="${baseUrl}vendas.html">
                            <i class='bx bx-list-ul'></i>
                            <span class="links_name">Vendas</span>
                        </a>
                    </li>
                    <li id="aba-notasfiscais">
                        <a href="${baseUrl}notasfiscais.html">
                            <i class='bx bx-barcode'></i>
                            <span class="links_name">Notas Fiscais</span>
                        </a>
                    </li>
                    <li id="aba-relatorios">
                        <a href="relatorios.html">
                            <i class='bx bx-pie-chart-alt-2'></i>
                            <span class="links_name">Relatórios</span>
                        </a>
                    </li>
                    <li id="aba-configuracoes">
                        <a href="${baseUrl}configuracoes.html">
                            <i class='bx bx-cog'></i>
                            <span class="links_name">Configurações</span>
                        </a>
                    </li>
                    <li class="log_out">
                    <a href="${baseUrl}login.html" onclick="logout()">
                            <i class='bx bx-log-out'></i>
                            <span class="links_name">Sair</span>
                        </a>
                    </li>`;

    document.querySelector("#menu").innerHTML = menu;
}
