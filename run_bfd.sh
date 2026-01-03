#!/bin/bash

# ============================================================
# BFD Docker Compose Helper Script (Extended with Debug Mode)
# ============================================================

set -e

COMMAND=$1
shift || true

BUILD_MODE="Release"

# Detect debug flag for build
if [[ "$1" == "--debug" ]]; then
  BUILD_MODE="Debug"
  shift
fi

case "$COMMAND" in

  build)
    echo "🔧 Building BFD Docker images (BUILD_TYPE=$BUILD_MODE)..."
    docker compose build --build-arg BUILD_TYPE=$BUILD_MODE
    ;;

  up)
    echo "🚀 Starting BFD initiator + responder..."
    #./up.sh
    docker compose up -d
    ;;

  logs)
    echo "📜 Showing logs..."
    docker compose logs -f
    ;;

  down)
    echo "🛑 Stopping and removing containers..."
    #./down.sh
    docker compose down
    ;;

  cli-init)
    echo "💬 Running bfdctl inside initiator container..."
    docker exec -it bfd_initiator /app/bfdctl "$@"
    ;;

  cli-resp)
    echo "💬 Running bfdctl inside responder container..."
    docker exec -it bfd_responder /app/bfdctl "$@"
    ;;

  shell-init)
    echo "🐚 Opening shell inside initiator..."
    docker exec -it bfd_initiator /bin/bash
    ;;

  shell-resp)
    echo "🐚 Opening shell inside responder..."
    docker exec -it bfd_responder /bin/bash
    ;;

  # -----------------------------
  # New: Run under gdbserver
  # -----------------------------
  gdb-init)
    echo "🐞 Attaching initiator under gdbserver (port 1235)..."
    docker exec -it bfd_initiator \
      sh -c "gdbserver 0.0.0.0:1235 --attach \$(ps aux | awk '{print \$11 \" \" \$2}' | grep app | awk '{print \$2}')" 
    ;;

  gdb-resp)
    echo "🐞 Attaching responder under gdbserver (port 1234)..."
    docker exec -it bfd_responder \
      sh -c "gdbserver 0.0.0.0:1234 --attach \$(ps aux | awk '{print \$11 \" \" \$2}' | grep app | awk '{print \$2}')" 
    ;;

  *)
    echo "Usage: ./run_bfd.sh <command> [args]"
    echo
    echo "Commands:"
    echo "  build [--debug]    Build Docker images (Release or Debug)"
    echo "  up                 Start initiator + responder"
    echo "  logs               Follow logs"
    echo "  down               Stop and remove containers"
    echo
    echo "  cli-init <cmd>     Run bfdctl inside initiator"
    echo "  cli-resp <cmd>     Run bfdctl inside responder"
    echo
    echo "  shell-init         Shell into initiator"
    echo "  shell-resp         Shell into responder"
    echo
    echo "  gdb-init           Run initiator under gdbserver"
    echo "  gdb-resp           Run responder under gdbserver"
    echo
    echo "Examples:"
    echo "  ./run_bfd.sh build"
    echo "  ./run_bfd.sh build --debug"
    echo "  ./run_bfd.sh up"
    echo "  ./run_bfd.sh cli-init \"show sessions\""
    echo "  ./run_bfd.sh init-gdb"
    echo "  ./run_bfd.sh down"
    ;;
esac
