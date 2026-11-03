import sys

CMDS = {"run", "discover", "profiles", "install-task", "uninstall-task", "open", "rebuild"}

if len(sys.argv) > 1 and sys.argv[1] in CMDS:
    import patrol
    patrol.main()
else:
    import gui
    gui.App().mainloop()
