/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.christofreichardt.crypto.schnorrsignature;

import java.math.BigInteger;

/**
 * Some precomputed {@link SchnorrGroup SchnorrGroup}s.
 * 
 * @author Christof Reichardt
 */
public class SchnorrGroups {

  /**
   * {@link SchnorrGroup SchnorrGroup}s whereby the bit length of is equal to 2048 and the bit length of q is equal to 512.
   */
  static public final SchnorrGroup[] DEFAULT = {
    new SchnorrGroup(
    new BigInteger("16841898101023068931410643926831264689842728942591354145616041810128140767330250523053484604681323006619733869827154660457928792780378116183836595643508679803015770906686829458990119551938793629839712069830445879746165932384555330995668799224812921251690827249812146757685772045214196682915454677644838531077866310596231100307284300123730687705973869385986005957285631388366698873944562286849748233633076445913642594243786535387915500571523892275706392216012506223388112351541551292596942988376090205443304074762634652580594231707636116103723915475117307631884274052754318189545396698402080933397165939187967315347553"),
    new BigInteger("8496390979930318073187061931363687721729557551643872214769272491337633803004607725964235028475936864359594960342902104820157171625356974529035883897619557")
    ),
    new SchnorrGroup(
    new BigInteger("20086957571991519636062661136125080924541674586262661014968904987928033209363827428654513546650018305971279772749703032244536895358577753423526754148560217898839776651477523732110183426932502210055950120573385700547208462621425346351461305338500790548202003652686850466590818406378754056964409836862826775793554257965209927590478184644145905225652502484600030611972150790928629495299885174561026155851925125601041015544335063842932510009776807557440141237111266014720518169854340328906864987639972749658026505762066824036029911607308720069605363111793600961835242413831193714936861940743633215972394622380386435678623"),
    new BigInteger("9099473709343992788082291461121603889740934357159312811715678148783494894013688406898972995726049572595090166961165858029808409631688814952391393176838361")
    ),
    new SchnorrGroup(
    new BigInteger("22060371024262142089093467376822523861079925074150101415224153067864138165424560427467242345389184200289541936649110886418582364312896506415949635654279254516030383204400819289634768115616897579994099630767820629606069081095274478063431610731386440533604695089559004801964032004173738958337315322225109985923659477277568935264922100176602110175091056077894643392487969169274113965949607020401439445027934526998325480587552012901819422763702304639650391551423112922314220056134542968322414729496485448133421926758994526124689989179786962376427797321329740079290834530124138221763110852578192329241541766639477211094327"),
    new BigInteger("10772180497804925784374276843540820927089050920146382901977126715290814898480616667149445933851266458879320766061459488445837849826234474634942539151025219")
    ),
    new SchnorrGroup(
    new BigInteger("20250315021201639232163942783615456428238115698819075604462877381006082852480458858860415838016680974958696390173798397197592759939763126814589154048182061824115028376128229054066738799875806484054149652894828864889769120379487433934047280326981190661684827268521336327155654026204580063663241619250721849315034434936782943572187812722244324192131415479438142617827751971275784235203996427630652976933313068823288041830451553063557703089396840360997379877090384237395358673394362693688278764840183237006886560937219627409801247515831124406387688127009408978212353668272006848983893186840465110613094679324731987398493"),
    new BigInteger("11950388264748858315083371646898961120992479192535254540914727621052370097409194857145905493460922506157661329954240633661870184633573350441968791228981553")
    ),
    new SchnorrGroup(
    new BigInteger("21759110157744224222780589251571102015915679697090935405059622894571745702015789439177730828023761913579015969038447006259213838314203624663513045568254942589055155430363754260031491455441906270606518711990568621879438765091627764253080769858472467619533815662953485188439822768572204035932224858450010289466290616332454174485199053611087438516227075291682966402793456164855512182027202419906598655367378742880133226420351727838140997114476202242043522707838127871168272925767467502826464037253907763889350769793431619776929414370764510179520823978923018292233764150036048903244894242943591499854106618610430991392981"),
    new BigInteger("9027586593829557785114345232454566711432340713556616484863282203119170818534595812062710724359462626826262533371896296786591961371376838827098320710741199")
    ),
    new SchnorrGroup(
    new BigInteger("18154600344385090128233843093028041883280745759491129591378063075864462720867738721008546265317645581822140821023671015164327667024235469246925005290254415268455785712906081669343559765686819267460202585444197031640926837800493319642631899971171984457480348196445472031407585822056244876076243168473819722037468016626509823303483274692387473167688845136379043825224688723876498369154267882976450537677758527769263043223344033655673884301441362869048278743128153667461536757287596766399022819266026158970322404567531955486112988149419359599413804922122962527108768941809955439041022906332945634378873230371333334385717"),
    new BigInteger("7598280647061375267756195459587344362046973338139598589818175454700530010756837822798273711952903034514019925238269242165132103484412983698024816435900503")
    ),
    new SchnorrGroup(
    new BigInteger("16697342569579359728313999633082899431924816720958178289177825529223296157291411858163960406580668252494379367472161030523874378290662986714404786669010136403884246746651771040961790823487758535967186627511089999421270960263962804102792356501278403772745565756900383234762180821034144821168076991638410302892164562051782672718758530817976013132216657763062238205062143330846833931095255675189414831967033601856468375866503828436087533904046730281603276913399548777861206579597428530244449228132787622481990281722377448662538004739317372586150896895236124176035251693852503163994907560019181192765461837761810088104409"),
    new BigInteger("12368659268912020152675102035846182956151484172049190803722575294452273954531279877510761100324820612903029562500009250044092168865401699578169868711219569")
    ),
    new SchnorrGroup(
    new BigInteger("21002545455690790817354598366395558699872884095509636231890536296184375074905940817606003271220547804741967210499523831212131397345549648875839787164403111908133107258137128762180092141284403906829036931523448492962227654215132759078616175800384816379197713257758382326575073002657331797723484755987225481957906749453159509118816636540735894991034332528265294771087296371792205295483696490407111125619717491011372403890381196572781741075235768872880746023926824939082545428792130000117354229042395801895719402368481517496030173417774694620489868912044841833796707854851791032731878302135145698260457453211998796888311"),
    new BigInteger("10410350568144120520262127688387522862246011764717465032173771145674505394744490045775324436210230061125858518593631604905888483065156104909559184880980273")
    ),
    new SchnorrGroup(
    new BigInteger("19066223611010065558647122450914358802483347667604641492550340784637509366554807721269703324527188270865721836998668005166276969218731927910499833719145220976087121181278619777618177850133954047053387097376301021157213585829979761459107087186059614373258474539083609241616674971322510912608994824511878068225547523234180203279895420521446858900496717207281487101564997013156116249274539225997544233712571328675402661927762043608674005233015892204000563327452091345050269231922901199347318550582673366011132143471185732912228427021588802566854329144266735840139559245509261998342873178673368712336815576020606157973553"),
    new BigInteger("9799980539115758814895304089375212288695191748113626411696862400143708907848827898060922428531357633030595897204664784376935782859234379577303129036338261")
    ),
    new SchnorrGroup(
    new BigInteger("26021867116485230593620989616605876468125316360788857992005840271298929708156567491764388064734783241318503732585655807003421988453285621643841822688390840024528175891737443962049813937834460794476287562990226370873644941986017288312124376928346033758461692176272227532004379736482108689721844297829931959776760896166187132138441961665780737958714393846688173597328181778839577926880866734700798519289171029899606156706454383192412172512361041305296324398184272343990171212560723903283190836970351371747809153953959392493779210155809014918923287535253446558427196743975960712049040974698488346297442958271072761327957"),
    new BigInteger("11649197244354697216542705304791581119184134090068218211946589513724078376671275689187933819530699651072268445834175303234605805784889874029982236474042569")
    ),
    new SchnorrGroup(
    new BigInteger("27473464784437325843626395712401910090945182744551994606087090587969526543495811309205376310467448846106940710844079340903095674596142205149443376798785713573762642587193377864835259070244378148189278357769772891460112104527547797167321122025993444783462260560767181136028562345527441251850024289210205282567603973848408312309214595605196061214566552598040029400742989190512223117453670028535977189735091198783346923211236232524581581810066179302928027328807406039191073538156589394583983633765667303374276271817057718714850901819410157780743187459321223889816458025460675539050449798630478209788636664758312167935267"),
    new BigInteger("12623505926867747031751932200654755564012325576517678584556964238728553395776781669112343732635285581158010651086603974401136485176033629223191311009072211")
    ),
    new SchnorrGroup(
    new BigInteger("17644072723831696372631828917971022783314712991982671648257191831758096665045961816138334683619692762828430218634725316460376397992799745716650063479785401986526648299697841516687559414993912492775305789005347287543133904678527080366674277474561661333298042094868849532223052716689102348934493287659766172467538900117968620932597704771964252730198690315305118006408765575666406902922649918958555833815549644447629551275194231993289257602068154433093064117621790154527376363593901671762440690120799936311196446056876992855934053838127835121604827063199938642873251746751072439344833123260137768177403650693870813174811"),
    new BigInteger("8946155658063152587086951463027071587424478335924663553825478160172678329029555013753851132980445299631940631508266658521136967815321297189919542107499881")
    ),
    new SchnorrGroup(
    new BigInteger("17477455874696289177872400021493317474760275876387658509863309043317169769003516205364642535948869346726473298057506617177631803661060836649536344363116974502707086328270644166285363816648313728884107859174750854306942549078143793759283305833552213348531969636084089765483313985201334757851022426106333763502817950011749384630332239584305233050830508727666535495098100311800086595543135028209388262827453047470657665166739401069476007996812548676524656738025393484012958699327395670036555393338095093149325019986540733862821852034068101614526252992985798431562439111207609526347428621154199245009946568715810828873511"),
    new BigInteger("10208105599294906902734133103712362667152900238634134449878963988898166292320605329281695495225417891881125386504380460943051987099498788924118489765750427")
    ),
    new SchnorrGroup(
    new BigInteger("26260155128079982237888886619285336820107699345354811254658422271699592046231839555873963380914179536530441815491568425690540312029281364479055194166139561298049030189187731322882852320088053603778686962420471241877345347543822167816630388461464148024730862970763495038380182561384696447276834619359924764440072827708355483204007375023275858525910634834248103845504470822746746278425357094588594136415375664854526203144700744416878290210745291971585427495656523321060506767194748689545150304239153539237289185100292570588065782121047096458922396275447371226434245785655258668837061468142982366230734183269888457523649"),
    new BigInteger("13203877356749621682764517869733352435790038725927387067629129222263182192880553636533056374974704797549401021910889086582889663290510154666651091808361273")
    ),
  };
}
