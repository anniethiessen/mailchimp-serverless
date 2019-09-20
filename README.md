# MailChimp Serverless

An experiment with Flask, Serverless, Docker, MailChimp, SQLAlchemy, Celery and AWS SQS.  
Last few commits untested.


## HOWTO
### pycurl installation:
sh -c "$(curl -fsSL https://raw.githubusercontent.com/Linuxbrew/install/master/install.sh)"
test -d ~/.linuxbrew && eval $(~/.linuxbrew/bin/brew shellenv)
test -d /home/linuxbrew/.linuxbrew && eval $(/home/linuxbrew/.linuxbrew/bin/brew shellenv)
test -r ~/.bash_profile && echo "eval \$($(brew --prefix)/bin/brew shellenv)" >>~/.bash_profile
echo "eval \$($(brew --prefix)/bin/brew shellenv)" >>~/.profile

### Token Retrieve
token = jws.dumps({'username': username})
