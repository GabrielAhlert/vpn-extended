# VPN eXtended (vpnx)

**VPN eXtended (`vpnx`)** é um utilitário de linha de comando escrito em Rust desenhado para encapsular as conexões do OpenVPN. Seu principal objetivo é fornecer uma camada de conveniência e segurança superior para o gerenciamento de múltiplas credenciais e tokens de autenticação de dois fatores (TOTP/MFA).

Ao invés de ter que digitar senhas extensas, buscar códigos no celular ou salvar arquivos de texto em claro no computador, o `vpnx` armazena tudo diretamente de forma criptografada no gerenciador de credenciais do seu Sistema Operacional.

## ✨ Funcionalidades Principais

- **Segurança Nativa:** Senhas e segredos TOTP são armazenados no cofre nativo do Sistema Operacional (Windows Credential Manager, macOS Keychain, Linux Secret Service). O projeto foi desenhado sob uma [auditoria de segurança rigorosa](https://github.com/GabrielAhlert/vpn-extended), garantindo _Zeroization_ de variáveis em memória e arquivos de autenticação protegidos.
- **Autenticação Automática de 2FA (TOTP):** Gere códigos TOTP em tempo real de forma blindada.
- **📷 Captura de QR Code na Tela:** Evite digitar a seed do OTP (que muitas vezes é enorme). Basta exibir o QR code da VPN no seu monitor e o `vpnx` localiza e extrai as credenciais diretamente da sua tela, importando para o banco sem qualquer input manual!
- **Wrapper Transparente:** Qualquer comando não-reconhecido pelo gerenciamento de credenciais do `vpnx` é repassado diretamente para a instalação do seu OpenVPN nativo, funcionando perfeitamente como um "Drop-in replacement".

## 🚀 Instalação

### Pré-requisitos
1. **Rust:** O projeto é compilado em Rust. Se você não possui a linguagem instalada, baixe pelo [rustup.rs](https://rustup.rs/).
2. **OpenVPN:** O `vpnx` requer que o executável `openvpn` esteja disponível na sua variável de ambiente `PATH`.

### Build
Clone este repositório e faça o build do executável otimizado:

```bash
git clone https://github.com/GabrielAhlert/vpn-extended.git
cd vpn-extended
cargo build --release
```

O binário final estará em `target/release/vpnx.exe` (no Windows) ou `target/release/vpnx` (no Linux/macOS). Para usá-lo livremente, mova este executável para um diretório presente no seu `PATH` ou instale com `cargo install --path .`.

---

## 🛠️ Como Usar

O `vpnx` baseia-se no conceito de **perfis** (configs). Cada perfil vincula uma credencial a um arquivo `.ovpn`.

### 1. Salvar uma nova VPN
```bash
vpnx save-auth minha_vpn_empresa
```

O programa iniciará um prompt iterativo:
1. Pede o caminho do arquivo `.ovpn`.
2. Pede seu _Username_.
3. Pede seu _Password_ de forma oculta.
4. Pede o _OTP Secret_ (Opcional).

> **💡 Dica Mágica do OTP:** Quando ele pedir o `OTP secret`, ao invés de digitar a seed textual base32, se você simplesmente digitar a palavra **`scan`**, o CLI fará uma leitura visual dos seus monitores! Basta deixar o QR Code do seu Authy/Google Authenticator visível em algum lugar da sua tela, e ele sugará a credencial direto da imagem.

### 2. Listar configurações
Veja quais conexões o sistema interceptará para você:
```bash
vpnx list-configs
```

### 3. Conectar
Inicie sua conexão transparente:
```bash
vpnx connect minha_vpn_empresa
```

Por padrão, a saída gerada será sintética e limpa (apenas erros, status e IPs de sucesso). Caso a conexão falhe ou não ande para a frente e você precisar debugar o log bruto do OpenVPN, ative o verboose flag `-v`:
```bash
vpnx connect minha_vpn_empresa -v
```

### 4. Apagar uma VPN salva
```bash
vpnx delete-auth minha_vpn_empresa
```
Isto exclui da memória e limpa irremediavelmente os secrets do cofre do SO.

### 5. Repasse de argumentos arbitrários
Tudo que não for comando interno (`save-auth`, `connect`...), rola direto no OpenVPN nativo:
```bash
vpnx --version
```
Retornará nativamente `OpenVPN 2.6.x x86_64...`.

---

## 🛡️ Aspectos de Segurança

Este projeto prioriza extrema cautela para não ser o novo elo fraco da sua conexão segura. Aspectos notáveis:
- Dependência `zeroize` é usada em todas as alocações de senhas textuais na heap do Rust para destruir essas variáveis na destruição do drop trait, previnindo leaks de despejos de memória e _swap_.
- Os arquivos temporários obrigatórios para se invocar o processo com openvpn com senha são forçados em flag unix a `0600` e eliminados ativamente ao fim do fork do processo VPN.
- Evita-se guardar qualquer configuração em claro, as configurações do `openvpn-wrapper.json` preservam somente nomes e caminhos de interface.

---

### Licença
Este projeto é providenciado nos modelos opensource. Sinta-se a vontade para forkar e adicionar mais scanners integrados ou novas integrações de secret engines corporativos (como o Hashicorp Vault).
