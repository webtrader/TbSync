tbSync.eas.onBeforeInjectIntoCardEditWindow = function (window) {
    //is this NewCard or EditCard?
    if (window.location.href=="chrome://messenger/content/addressbook/abNewCardDialog.xul") {
        //always inject if NewCard, but hide if selected ab is not EAS
        return true;        
    } else {    
        //Only inject, if this card is an EAS card
        let cards = window.opener.GetSelectedAbCards();

        if (cards.length == 1) {
            let aParentDirURI = tbSync.getUriFromPrefId(cards[0].directoryId.split("&")[0]);
            if (aParentDirURI) { //could be undefined
                let folders = tbSync.db.findFoldersWithSetting("target", aParentDirURI);
                if (folders.length > 0 && tbSync.db.getAccountSetting(folders[0].account, "provider") == "eas") return true;
            }
        }
    }
    
    return false; //this could be made switchable here, so EAS fields are always present
}


tbSync.eas.onInjectIntoCardEditWindow = function (window) {
    if (window.location.href=="chrome://messenger/content/addressbook/abNewCardDialog.xul") {
        //add handler for ab switching    
        tbSync.eas.onAbSelectChangeNewCard(window);
        window.document.getElementById("abPopup").addEventListener("select", function () {tbSync.eas.onAbSelectChangeNewCard(window);}, false);
        RegisterSaveListener(tbSync.eas.onSaveCard);
    } else {
        window.RegisterLoadListener(tbSync.eas.onLoadCard);
        window.RegisterSaveListener(tbSync.eas.onSaveCard);

        //if this window was open during inject, load the extra fields
        if (gEditCard) tbSync.eas.onLoadCard(gEditCard.card, window.document);
    }
}

tbSync.eas.onAbSelectChangeNewCard = function(window) {
    let folders = tbSync.db.findFoldersWithSetting("target", window.document.getElementById("abPopup").value);
    let eas = (folders.length > 0 && tbSync.db.getAccountSetting(folders[0].account, "provider") == "eas");
    window.document.getElementById("easFields1Tab").hidden = !eas;
    window.document.getElementById("easFields2Tab").hidden = !eas;
    window.document.getElementById("MiddleNameContainer").hidden = !eas;
    window.document.getElementById("Email3AddressContainer").hidden = !eas;
}

//What to do, if card is opened for edit in UI (listener only registerd for EAS cards, so no need to check again)
tbSync.eas.onLoadCard = function (aCard, aDocument) {
    //aDocument.defaultView.console.log("read:" + aCard.getProperty("EAS-MiddleName", ""));
    let items = aDocument.getElementsByClassName("easProperty");
    for (let i=0; i < items.length; i++)
    {
        items[i].value = aCard.getProperty(items[i].id, "");
    }
}


//What to do, if card is saved in UI (listener is registered for all cards, so we need to check for EAS cards)
tbSync.eas.onSaveCard = function (aCard, aDocument) {
    //use the hidden status of easFields1Tab to know, if this is an eas card
    if (window.document.getElementById("easFields1Tab") && !window.document.getElementById("easFields1Tab").hidden) {
        let items = aDocument.getElementsByClassName("easProperty");
        for (let i=0; i < items.length; i++)
        {
            aCard.setProperty(items[i].id, items[i].value);
        }
    }
}
