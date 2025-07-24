#!/usr/bin/env bash

# -------- Default Configuration --------
ENVNAME="${ENVNAME:-dev}"
STACK="${STACK:---all}"
PROFILE="${PROFILE:-piercuta-dev}"
CONCURRENCY="${CONCURRENCY:-3}"
OUTPUT="${OUTPUT:-cdk.out}"

# -------- Commands --------


case "$1" in
  install)
    echo "📦 Installing dependencies..."
    pip install -r requirements.txt
    ;;

  synth)
    echo "🧪 Synthesizing CDK for envname=$ENVNAME with output=$OUTPUT..."
    cdk synth --context env="$ENVNAME" --profile "$PROFILE" --output "$OUTPUT"
    ;;

  deploy)
    echo "🚀 Deploying stack ($STACK) for envname=$ENVNAME with concurrency=$CONCURRENCY and output=$OUTPUT..."
    cdk deploy $STACK --concurrency $CONCURRENCY --context env="$ENVNAME" --profile "$PROFILE" --output "$OUTPUT" --require-approval never
    ;;

  diff)
    echo "🔍 Diffing stack ($STACK) for envname=$ENVNAME with output=$OUTPUT..."
    cdk diff $STACK --context env="$ENVNAME" --profile "$PROFILE" --output "$OUTPUT"
    ;;

  destroy)
    echo "💣 Destroying stack ($STACK) for envname=$ENVNAME with concurrency=$CONCURRENCY and output=$OUTPUT..."
    cdk destroy $STACK --concurrency $CONCURRENCY --context env="$ENVNAME" --profile "$PROFILE" --output "$OUTPUT" --require-approval never
    ;;


  clean)
    echo "🧹 Cleaning project..."
    rm -rf .pytest_cache .venv __pycache__ .cdk.staging cdk.out *.egg-info
    ;;

  help|*)
    echo "📘 Usage: [ENVNAME=env] [STACK=name] [PROFILE=profile] [CONCURRENCY=concurrency] [OUTPUT=output] ./cdk-tools.sh <command>"
    echo ""
    echo "Commands:"
    echo "  install           Installer les dépendances Python"
    echo "  synth             Synthétiser la stack CDK"
    echo "  deploy            Déployer la stack (ou toutes)"
    echo "  diff              Voir les différences"
    echo "  destroy           Supprimer la stack"
    echo "  clean             Supprimer les fichiers temporaires"
    echo "  help              Afficher cette aide"
    ;;
esac
# ENVNAME=test STACK=NetworkStack OUTPUT=toto ./cdk-tools.sh deploy
