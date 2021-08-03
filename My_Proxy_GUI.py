
import sys
import PyQt5.QtWidgets as widgets
import PyQt5.QtGui as gui
import PyQt5.QtCore as core

class MyApp(widgets.QWidget):

    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        forward = widgets.QPushButton('Forward', self)
        drop = widgets.QPushButton('Drop', self)
        intercept = widgets.QPushButton('Intercept', self)
        edittext = widgets.QTextEdit()

        self.Main_Layout(forward, drop, intercept, edittext)
        self.Main_Handler(forward, drop, intercept, edittext)

        self.setWindowIcon(gui.QIcon('logo.png'))
        self.setWindowTitle('Apollo Proxy')
        self.setGeometry(600, 400, 800, 600)
        self.show()

    def Main_Layout(self, forward, drop, intercept, edittext):
        intercept.resize(100, 30)
        forward.resize(100, 30)
        drop.resize(100, 30)

        intercept.move(50, 50)
        forward.move(150, 50)
        drop.move(250, 50)

        intercept.setCheckable(True)
        intercept.toggle()
        forward.setEnabled(False)
        drop.setEnabled(False)

    def Main_Handler(self, forward, drop, intercept, edittext):
        pass



if __name__ == '__main__':
   app = widgets.QApplication(sys.argv)
   ex = MyApp()
   sys.exit(app.exec_())
