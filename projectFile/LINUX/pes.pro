QT += widgets gui core

SOURCES += \
    util.c \
    securechannel.c \
    sc_functions.c \
    pup_encryption_functions.c \
    mainForm.cpp \
    main.cpp \
    hidapi.c \
    communication.c \

HEADERS += \
    util.h \
    securechannel.h \
    sc_functions.h \
    pup_encryption_functions.h \
    mainForm.h \
    hidapi.h \
    communication.h \
    common.h \

RESOURCES += \
    pes_resources.qrc

unix:!macx:!symbian: LIBS += -lusb-1.0
unix:!macx:!symbian: LIBS += -lcrypto
