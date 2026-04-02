"""`server` 命令入口。"""


def register(subparsers, parent):
    parser = subparsers.add_parser("server", help="启动 HTTP API 服务", parents=[parent])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--config", dest="server_config", default=None,
                        help="配置文件路径；未提供时沿用全局 -c/--config。")
    return {"server": run}


def run(args, config, runtime):
    from api_server import run_api_server

    host = args.host
    port = args.port
    config_path = getattr(args, "server_config", None) or getattr(args, "config", "config.yaml")

    runtime.console.print(
        f"[green]启动 API 服务:[/] {host}:{port}\n"
        f"[dim]配置文件: {config_path}\n"
        f"可用路由: /health, /api/analyze, /api/analyzer, /api/validate, /api/batch-validate[/]"
    )
    run_api_server(host, port, config_path=config_path)
