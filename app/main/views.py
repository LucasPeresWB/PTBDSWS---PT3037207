from flask import render_template, redirect, url_for, flash, request
from flask_login import current_user, login_required

from . import main
from .forms import NameForm

from app.models import (
    User,
    inicializar_banco,
    carregar_emails,
    carregar_usuarios,
    adicionar_usuario,
    editar_usuario,
    excluir_usuario
)

from app.email import send_email

inicializar_banco()


@main.route('/', methods=['GET', 'POST'])
def index():
    form = NameForm()

    if current_user.is_authenticated and form.validate_on_submit():
        nome = form.name.data
        novo_usuario = adicionar_usuario(nome)

        if novo_usuario:
            send_email(
                subject='Novo usuário',
                new_username=nome,
                additional_email=form.email.data
            )
            flash('Usuário cadastrado e e-mails enviados com sucesso.', 'success')
        else:
            flash('Esse usuário já está cadastrado.', 'warning')

        return redirect(url_for('main.index'))

    if current_user.is_authenticated and current_user.confirmed:
        usuarios = User.query.order_by(User.id).all()
    else:
        usuarios = []

    return render_template(
        'index.html',
        form=form if current_user.is_authenticated else None,
        usuarios=usuarios
    )


@main.route('/emailsEnviados')
@login_required
def emails_enviados():
    emails = carregar_emails()
    return render_template('emailsEnviados.html', emails=emails)


@main.route('/editar/<nome>', methods=['POST'])
@login_required
def editar(nome):
    novo_nome = request.form.get('novo_nome', '').strip()

    if not novo_nome:
        flash('O nome não pode ficar vazio.', 'danger')
    elif editar_usuario(nome, novo_nome):
        flash('Usuário editado com sucesso.', 'success')
    else:
        flash('Não foi possível editar. Verifique o nome ou as permissões.', 'danger')

    return redirect(url_for('main.index'))


@main.route('/excluir/<nome>', methods=['POST'])
@login_required
def excluir(nome):
    if excluir_usuario(nome):
        flash('Usuário excluído com sucesso.', 'success')
    else:
        flash('Não foi possível excluir esse usuário.', 'danger')

    return redirect(url_for('main.index'))