from dash import Dash, html, dash_table, dcc
import dash_bootstrap_components as dbc
import plotly.express as px
from dash_bootstrap_templates import load_figure_template
from pathlib import Path
import pandas as pd

from dashboard_data_parser import *
from honeypy import *

base_dir = Path(__file__).parent.parent

creds_audits_log_local_file_path = base_dir / 'ssh_honeypy' / 'log_files' / 'creds_audits.log.1'
cmd_audits_log_local_file_path = base_dir / 'ssh_honeypy' / 'log_files' / 'cmd_audits.log'


creds_audits_log_df = parse_creds_audits_log(creds_audits_log_local_file_path)

all_cmd_logs = []
if cmd_audits_log_local_file_path.exists():
    df = parse_cmd_audits_log(cmd_audits_log_local_file_path)
    all_cmd_logs.append(df)
else:
    cmd_audits_log_df = pd.DataFrame(columns=['IP Address', 'Command'])

cmd_audits_log_df = pd.concat(all_cmd_logs, ignore_index=True) if all_cmd_logs else pd.DataFrame(columns=['IP Address', 'Command'])


top_ip_address = top_10_calculator(creds_audits_log_df, "ip_address")
top_usernames = top_10_calculator(creds_audits_log_df, "username")
top_passwords = top_10_calculator(creds_audits_log_df, "password")
top_cmds = top_10_calculator(cmd_audits_log_df, "Command")

load_figure_template(["darkly"])
dbc_css = ("https://cdn.jsdelivr.net/gh/AnnMarieW/dash-bootstrap-templates@V1.0.4/dbc.min.css")


image = 'assets/images/title1.png'

app = Dash(__name__, external_stylesheets=[dbc.themes.DARKLY, dbc_css])

app.title = "HONEYPOT"
app._favicon = "../assets/images/honeypy-favicon.ico"

tables = html.Div([
    dbc.Row([
        dbc.Col(
            dash_table.DataTable(
                data=creds_audits_log_df.to_dict('records'),
                columns=[{"name": "IP Address", 'id': 'ip_address'}],
                style_table={'width': '100%', 'color': 'black'},
                style_cell={'textAlign': 'left', 'color': '#39FF14'},
                style_header={'fontWeight': 'bold'},
                page_size=10
            ),
        ),
        dbc.Col(
            dash_table.DataTable(
                data=creds_audits_log_df.to_dict('records'),
                columns=[{"name": "Usernames", 'id': 'username'}],
                style_table={'width': '100%'},
                style_cell={'textAlign': 'left', 'color': '#39FF14'},
                style_header={'fontWeight': 'bold'},
                page_size=10
            ),
        ),
        dbc.Col(
            dash_table.DataTable(
                data=creds_audits_log_df.to_dict('records'),
                columns=[{"name": "Passwords", 'id': 'password'}],
                style_table={'width': '100%', 'justifyContent': 'center'},
                style_cell={'textAlign': 'left', 'color': '#39FF14'},
                style_header={'fontWeight': 'bold'},
                page_size=10
            ),
        ),
    ])
])

apply_table_theme = html.Div(
    [tables],
    className="dbc"
)

app.layout = dbc.Container([
   
    html.Div([html.Img(src=image, style={'height': '25%', 'width': '25%'})], style={'textAlign': 'center'}, className='dbc'),
    
    dbc.Row([
        dbc.Col(dcc.Graph(figure=px.bar(top_ip_address, x="ip_address", y='count')), width=4),
        dbc.Col(dcc.Graph(figure=px.bar(top_usernames, x='username', y='count')), width=4),
        dbc.Col(dcc.Graph(figure=px.bar(top_passwords, x='password', y='count'))),
    ], align='center', class_name='mb-4'),

    
    dbc.Row([
        dbc.Col(dcc.Graph(figure=px.bar(top_cmds, x='Command', y='count')), style={'width': '33%', 'display': 'inline-block'})
    ], align='center', class_name='mb-4'),

    
    html.Div([
        html.H3(
            "INTELLIGENCE DATA", 
            style={'textAlign': 'center', "font-family": 'Consolas, sans-serif', 'font-weight': 'bold', 'color': 'yellow'}, 
        ),
    ]),
    
    apply_table_theme    
])

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")